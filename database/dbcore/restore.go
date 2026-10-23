package dbcore

import (
	"archive/zip"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/komari-monitor/komari/cmd/flags"
)

const (
	restoreMarkerFile   = "komari-backup-markup"
	restoreDatabaseFile = "komari.db"

	maxRestoreEntries       = 100_000
	maxRestoreExpandedBytes = 4 << 30 // 4 GiB
)

// restoreSwapHook lets tests inject a failure right before the data directory
// is swapped. Production code leaves it nil.
var restoreSwapHook func(dataDir, stagingDir string) error

// restoreActivateHook lets tests inject a failure after the current data was
// moved aside but before the staged data is activated, exercising rollback.
var restoreActivateHook func(previousDir, dataDir string) error

// restoreStagedBackup validates a staged archive in an isolated directory and
// only then swaps it with dataDir. Until validation succeeds the current data
// is never modified, and a failed swap restores the original directory.
//
// It returns the directory holding the previous data (empty when there was no
// previous directory), which callers keep for rollback and diagnostics.
func restoreStagedBackup(archivePath, dataDir string) (string, error) {
	cleanDataDir := filepath.Clean(dataDir)
	stageParent := filepath.Dir(cleanDataDir)
	if err := os.MkdirAll(stageParent, 0755); err != nil {
		return "", fmt.Errorf("create restore staging parent: %w", err)
	}
	stagingDir, err := os.MkdirTemp(stageParent, ".komari-restore-*")
	if err != nil {
		return "", fmt.Errorf("create restore staging directory: %w", err)
	}
	// After a successful swap the staging path no longer exists, so this only
	// removes the failed attempt.
	defer os.RemoveAll(stagingDir)

	if err := extractArchive(archivePath, stagingDir); err != nil {
		return "", err
	}
	if err := validateRestoredData(stagingDir); err != nil {
		return "", err
	}
	// The marker only exists to identify uploads; it is not part of the data.
	_ = os.Remove(filepath.Join(stagingDir, restoreMarkerFile))

	if restoreSwapHook != nil {
		if err := restoreSwapHook(cleanDataDir, stagingDir); err != nil {
			return "", err
		}
	}
	return swapDataDir(cleanDataDir, stagingDir)
}

// extractArchive extracts archivePath into dstDir with entry type, path and
// size validation. Every entry is checked before it is written.
func extractArchive(archivePath, dstDir string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open backup archive: %w", err)
	}
	defer reader.Close()

	if len(reader.File) > maxRestoreEntries {
		return fmt.Errorf("backup archive has too many files: %d", len(reader.File))
	}
	absDst, err := filepath.Abs(dstDir)
	if err != nil {
		return fmt.Errorf("resolve restore directory: %w", err)
	}
	if err := os.MkdirAll(absDst, 0755); err != nil {
		return fmt.Errorf("create restore directory: %w", err)
	}

	var expanded uint64
	for _, entry := range reader.File {
		relative, err := safeArchivePath(entry.Name)
		if err != nil {
			return err
		}
		target := filepath.Join(absDst, relative)
		if !pathWithin(absDst, target) {
			return fmt.Errorf("backup entry escapes the restore directory: %s", entry.Name)
		}

		mode := entry.FileInfo().Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("backup entry is a symbolic link: %s", entry.Name)
		}
		if mode.IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", relative, err)
			}
			continue
		}
		if !mode.IsRegular() {
			return fmt.Errorf("backup entry is not a regular file: %s", entry.Name)
		}

		size := entry.UncompressedSize64
		if size > maxRestoreExpandedBytes || expanded > maxRestoreExpandedBytes-size {
			return fmt.Errorf("backup archive expands beyond the %d byte limit", uint64(maxRestoreExpandedBytes))
		}
		expanded += size

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return fmt.Errorf("create parent directory for %s: %w", relative, err)
		}
		if err := extractArchiveFile(entry, target, int64(size)); err != nil {
			return err
		}
	}
	return nil
}

func extractArchiveFile(entry *zip.File, target string, declaredSize int64) error {
	source, err := entry.Open()
	if err != nil {
		return fmt.Errorf("open backup entry %s: %w", entry.Name, err)
	}
	defer source.Close()

	destination, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create restored file %s: %w", entry.Name, err)
	}
	// A lying header must not expand beyond the declared size.
	written, copyErr := io.Copy(destination, io.LimitReader(source, declaredSize+1))
	closeErr := destination.Close()
	if copyErr != nil {
		return fmt.Errorf("write restored file %s: %w", entry.Name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close restored file %s: %w", entry.Name, closeErr)
	}
	if written > declaredSize {
		return fmt.Errorf("backup entry %s is larger than declared", entry.Name)
	}
	return nil
}

// safeArchivePath rejects absolute paths, drive letters, parent traversal and
// link-style escapes. Both separators are inspected so archives created on
// another platform cannot escape on Windows (and vice versa).
func safeArchivePath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("invalid backup entry name")
	}
	normalized := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(normalized, "/") || filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("absolute path in backup archive: %s", name)
	}
	if len(normalized) >= 2 && normalized[1] == ':' {
		return "", fmt.Errorf("absolute path in backup archive: %s", name)
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return "", fmt.Errorf("path traversal in backup archive: %s", name)
		}
	}
	cleaned := path.Clean(normalized)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path traversal in backup archive: %s", name)
	}
	return filepath.FromSlash(cleaned), nil
}

func pathWithin(base, target string) bool {
	relative, err := filepath.Rel(base, target)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

// validateRestoredData checks the required files and that the restored SQLite
// database can actually be opened before the current data is replaced.
func validateRestoredData(dir string) error {
	marker, err := os.Lstat(filepath.Join(dir, restoreMarkerFile))
	if err != nil || !marker.Mode().IsRegular() {
		return fmt.Errorf("invalid backup: missing %s", restoreMarkerFile)
	}
	if flags.ApplyDatabaseTypeNormalization() != flags.DatabaseTypeSQLite {
		return nil
	}
	databasePath := filepath.Join(dir, restoreDatabaseFile)
	info, err := os.Lstat(databasePath)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("invalid backup: missing %s", restoreDatabaseFile)
	}
	if err := validateSQLiteDatabase(databasePath); err != nil {
		return fmt.Errorf("invalid backup database: %w", err)
	}
	return nil
}

func validateSQLiteDatabase(databasePath string) error {
	dsn := "file:" + filepath.ToSlash(databasePath) + "?mode=ro"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// quick_check detects structural corruption without scanning every index,
	// keeping startup validation bounded for large databases.
	var result string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&result); err != nil {
		return err
	}
	if !strings.EqualFold(result, "ok") {
		return fmt.Errorf("integrity check failed: %s", result)
	}
	var tables int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		return fmt.Errorf("database contains no tables")
	}
	return nil
}

// swapDataDir moves the current data aside and activates staging. If the
// activation fails, the previous directory is restored before returning.
func swapDataDir(dataDir, stagingDir string) (string, error) {
	if _, err := os.Stat(dataDir); err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("inspect current data: %w", err)
		}
		if err := os.Rename(stagingDir, dataDir); err != nil {
			return "", fmt.Errorf("activate restored data: %w", err)
		}
		return "", nil
	}

	previousDir := nextPreviousDataDir(dataDir)
	if err := os.Rename(dataDir, previousDir); err != nil {
		return "", fmt.Errorf("move current data aside: %w", err)
	}
	if restoreActivateHook != nil {
		if hookErr := restoreActivateHook(previousDir, dataDir); hookErr != nil {
			if rollbackErr := os.Rename(previousDir, dataDir); rollbackErr != nil {
				return "", fmt.Errorf("activate restored data: %v (rollback failed: %v; previous data kept at %s)", hookErr, rollbackErr, previousDir)
			}
			return "", hookErr
		}
	}
	if err := os.Rename(stagingDir, dataDir); err != nil {
		if rollbackErr := os.Rename(previousDir, dataDir); rollbackErr != nil {
			return "", fmt.Errorf("activate restored data: %v (rollback failed: %v; previous data kept at %s)", err, rollbackErr, previousDir)
		}
		return "", fmt.Errorf("activate restored data: %w", err)
	}
	return previousDir, nil
}

func nextPreviousDataDir(dataDir string) string {
	parent := filepath.Dir(dataDir)
	base := ".komari-previous-data-" + time.Now().UTC().Format("20060102-150405")
	for attempt := 0; ; attempt++ {
		candidate := filepath.Join(parent, base)
		if attempt > 0 {
			candidate = filepath.Join(parent, fmt.Sprintf("%s-%d", base, attempt))
		}
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}
