package dbcore

import (
	"archive/zip"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/komari-monitor/komari/cmd/flags"
)

type testZipEntry struct {
	name string
	body string
	mode fs.FileMode
}

func writeTestArchive(t *testing.T, archivePath string, entries []testZipEntry) {
	t.Helper()
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	writer := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(entry.mode)
		destination, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create archive entry %s: %v", entry.name, err)
		}
		if _, err := destination.Write([]byte(entry.body)); err != nil {
			t.Fatalf("write archive entry %s: %v", entry.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive file: %v", err)
	}
}

func writeTestDatabase(t *testing.T, databasePath string) {
	t.Helper()
	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("create test table: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (name) VALUES ('restore-test')"); err != nil {
		t.Fatalf("insert test row: %v", err)
	}
}

// restoreFixture prepares ./data with a current file and a backup.zip.
func restoreFixture(t *testing.T, entries []testZipEntry) (root, dataDir, archivePath string) {
	t.Helper()
	previousType := flags.DatabaseType
	flags.DatabaseType = "sqlite"
	t.Cleanup(func() { flags.DatabaseType = previousType })

	root = t.TempDir()
	dataDir = filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatalf("create data dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "current.txt"), []byte("current data"), 0644); err != nil {
		t.Fatalf("write current data: %v", err)
	}
	archivePath = filepath.Join(dataDir, "backup.zip")
	writeTestArchive(t, archivePath, entries)
	return root, dataDir, archivePath
}

func validBackupEntries(t *testing.T) []testZipEntry {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "komari.db")
	writeTestDatabase(t, databasePath)
	databaseBytes, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("read test database: %v", err)
	}
	return []testZipEntry{
		{name: restoreMarkerFile, body: "komari-backup", mode: 0644},
		{name: restoreDatabaseFile, body: string(databaseBytes), mode: 0644},
		{name: "theme/config.json", body: `{"name":"restored"}`, mode: 0644},
	}
}

func assertCurrentDataIntact(t *testing.T, dataDir string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dataDir, "current.txt"))
	if err != nil || string(body) != "current data" {
		t.Fatalf("current data was modified: body=%q err=%v", body, err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "backup.zip")); err != nil {
		t.Fatalf("backup archive was removed after a failed restore: %v", err)
	}
}

func TestRestoreStagedBackupReplacesData(t *testing.T) {
	_, dataDir, archivePath := restoreFixture(t, validBackupEntries(t))

	previousDir, err := restoreStagedBackup(archivePath, dataDir)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if previousDir == "" {
		t.Fatal("restore did not preserve the previous data directory")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "theme", "config.json")); err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "current.txt")); !os.IsNotExist(err) {
		t.Fatal("current data was not replaced")
	}
	if _, err := os.Stat(filepath.Join(dataDir, restoreMarkerFile)); !os.IsNotExist(err) {
		t.Fatal("restore marker was not removed from the restored data")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "backup.zip")); !os.IsNotExist(err) {
		t.Fatal("consumed backup archive is still in the data directory")
	}
	if _, err := os.Stat(filepath.Join(previousDir, "current.txt")); err != nil {
		t.Fatalf("previous data is not available for rollback: %v", err)
	}
	if _, err := os.Stat(filepath.Join(previousDir, "backup.zip")); err != nil {
		t.Fatalf("previous data lost the backup archive: %v", err)
	}
	if filepath.Dir(filepath.Clean(previousDir)) != filepath.Clean(dataDir) {
		t.Fatalf("previous data %q must stay inside the data dir %q", previousDir, dataDir)
	}
}

// TestRestoreStagingStaysInsideDataDir proves the restore does not depend on
// the parent directory: staging lives inside the data directory, so a
// deployment that only makes ./data writable still works.
func TestRestoreStagingStaysInsideDataDir(t *testing.T) {
	_, dataDir, archivePath := restoreFixture(t, validBackupEntries(t))

	var staging string
	restoreSwapHook = func(dataDir, stagingDir string) error {
		staging = stagingDir
		return errors.New("stop before the swap")
	}
	t.Cleanup(func() { restoreSwapHook = nil })

	if _, err := restoreStagedBackup(archivePath, dataDir); err == nil {
		t.Fatal("restore ignored the injected pre-swap failure")
	}
	if staging == "" {
		t.Fatal("swap hook was not called")
	}
	if !pathWithin(filepath.Clean(dataDir), filepath.Clean(staging)) || staging == filepath.Clean(dataDir) {
		t.Fatalf("staging dir %q is not inside the data dir %q", staging, dataDir)
	}
	assertCurrentDataIntact(t, dataDir)
}

// TestRestoreWorksWhenParentDirectoryIsReadOnly covers the reported deployment
// shape: only ./data is writable.
func TestRestoreWorksWhenParentDirectoryIsReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory write permission cannot be restricted on Windows; staging location is covered by TestRestoreStagingStaysInsideDataDir")
	}
	_, dataDir, archivePath := restoreFixture(t, validBackupEntries(t))
	parent := filepath.Dir(dataDir)
	if err := os.Chmod(parent, 0500); err != nil {
		t.Fatalf("make parent read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })

	previousDir, err := restoreStagedBackup(archivePath, dataDir)
	if err != nil {
		t.Fatalf("restore failed with a read-only parent directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "theme", "config.json")); err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(previousDir, "current.txt")); err != nil {
		t.Fatalf("previous data is not available for rollback: %v", err)
	}
}

// TestBackupSkipsRestoreWorkDirs keeps the restore machinery out of backup
// archives so it is never restored as data or accumulated across restores.
func TestBackupSkipsRestoreWorkDirs(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	for _, dir := range []string{restoreStagingDirName, restorePreviousDirName} {
		if err := os.MkdirAll(filepath.Join(dataDir, dir), 0755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, dir, "komari.db"), []byte("stale"), 0644); err != nil {
			t.Fatalf("write file in %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataDir, "komari.db"), []byte("current"), 0644); err != nil {
		t.Fatalf("write data file: %v", err)
	}

	archive := filepath.Join(root, "snapshot.zip")
	if err := zipDirectoryExcluding(dataDir, archive, nil); err != nil {
		t.Fatalf("zip data dir: %v", err)
	}
	reader, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer reader.Close()

	names := make(map[string]struct{})
	for _, entry := range reader.File {
		names[entry.Name] = struct{}{}
	}
	if _, ok := names["komari.db"]; !ok {
		t.Fatal("archive is missing the real database")
	}
	for name := range names {
		if strings.HasPrefix(name, restoreStagingDirName) || strings.HasPrefix(name, restorePreviousDirName) {
			t.Fatalf("restore work dir leaked into the backup: %s", name)
		}
	}
}

func TestRestoreRejectsTraversalAndKeepsData(t *testing.T) {
	entries := validBackupEntries(t)
	root, dataDir, archivePath := restoreFixture(t, entries)
	// Re-write the archive with a traversal entry.
	writeTestArchive(t, archivePath, append(entries, testZipEntry{name: "../escaped.txt", body: "escaped", mode: 0644}))

	if _, err := restoreStagedBackup(archivePath, dataDir); err == nil {
		t.Fatal("restore accepted a path traversal entry")
	}
	assertCurrentDataIntact(t, dataDir)
	if _, err := os.Stat(filepath.Join(root, "escaped.txt")); !os.IsNotExist(err) {
		t.Fatal("traversal entry escaped the staging directory")
	}
}

func TestRestoreRejectsAbsoluteAndWindowsPaths(t *testing.T) {
	for _, name := range []string{"/abs.txt", "C:/windows.txt", `..\windows.txt`} {
		entries := append(validBackupEntries(t), testZipEntry{name: name, body: "x", mode: 0644})
		_, dataDir, archivePath := restoreFixture(t, entries)
		if _, err := restoreStagedBackup(archivePath, dataDir); err == nil {
			t.Fatalf("restore accepted unsafe entry %q", name)
		}
		assertCurrentDataIntact(t, dataDir)
	}
}

func TestRestoreRejectsSymlinkEntry(t *testing.T) {
	entries := append(validBackupEntries(t),
		testZipEntry{name: "link", body: "/etc/passwd", mode: fs.ModeSymlink | 0777})
	_, dataDir, archivePath := restoreFixture(t, entries)
	if _, err := restoreStagedBackup(archivePath, dataDir); err == nil {
		t.Fatal("restore accepted a symbolic link entry")
	}
	assertCurrentDataIntact(t, dataDir)
}

func TestRestoreRejectsMissingDatabase(t *testing.T) {
	entries := []testZipEntry{
		{name: restoreMarkerFile, body: "komari-backup", mode: 0644},
		{name: "theme/config.json", body: "{}", mode: 0644},
	}
	_, dataDir, archivePath := restoreFixture(t, entries)
	if _, err := restoreStagedBackup(archivePath, dataDir); err == nil {
		t.Fatal("restore accepted an archive without a database")
	}
	assertCurrentDataIntact(t, dataDir)
}

func TestRestoreRejectsCorruptDatabase(t *testing.T) {
	entries := []testZipEntry{
		{name: restoreMarkerFile, body: "komari-backup", mode: 0644},
		{name: restoreDatabaseFile, body: "this is not a sqlite database", mode: 0644},
	}
	_, dataDir, archivePath := restoreFixture(t, entries)
	if _, err := restoreStagedBackup(archivePath, dataDir); err == nil {
		t.Fatal("restore accepted a corrupt database")
	}
	assertCurrentDataIntact(t, dataDir)
}

func TestRestoreKeepsDataWhenSwapFails(t *testing.T) {
	_, dataDir, archivePath := restoreFixture(t, validBackupEntries(t))
	restoreSwapHook = func(string, string) error { return errors.New("injected pre-swap failure") }
	t.Cleanup(func() { restoreSwapHook = nil })

	if _, err := restoreStagedBackup(archivePath, dataDir); err == nil {
		t.Fatal("restore ignored the injected swap failure")
	}
	assertCurrentDataIntact(t, dataDir)
}

func TestRestoreRollsBackWhenActivationFails(t *testing.T) {
	_, dataDir, archivePath := restoreFixture(t, validBackupEntries(t))
	restoreActivateHook = func(string, string) error { return errors.New("injected activation failure") }
	t.Cleanup(func() { restoreActivateHook = nil })

	if _, err := restoreStagedBackup(archivePath, dataDir); err == nil {
		t.Fatal("restore ignored the injected activation failure")
	}
	assertCurrentDataIntact(t, dataDir)
}
