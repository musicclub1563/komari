package plugin

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/models"
)

var (
	installMu    sync.Mutex
	installLocks = make(map[string]chan struct{})
)

// installActivateHook lets tests inject a failure right before the staged
// package is moved into place, exercising the rollback path. Production code
// leaves it nil.
var installActivateHook func(stagingDir, targetDir string) error

// lockInstall serializes the swap phase for one plugin short. Concurrent
// updates of the same plugin must not interleave with a rollback.
func lockInstall(short string) func() {
	installMu.Lock()
	slot := installLocks[short]
	if slot == nil {
		slot = make(chan struct{}, 1)
		installLocks[short] = slot
	}
	installMu.Unlock()
	slot <- struct{}{}
	return func() { <-slot }
}

// InstallZip validates a plugin ZIP and extracts it into DataDir/<short>.
// The archive must contain komari-plugin.json at its root. Archive limits
// mirror the theme package format; path-traversal entries reject the whole
// package instead of being skipped.
//
// The package is extracted into an isolated staging directory first and is
// only moved into place after the manifest, entry and page files validated.
// Until then the installed version is never touched, so an invalid update
// cannot delete or unmount the running plugin. The swap renames directories
// inside DataDir (same filesystem), and both the activation and the reload
// roll back to the previous version with its persisted enabled state on
// failure. Nothing from the archive is executed before the swap.
func InstallZip(zipPath string) (models.Plugin, error) {
	var info models.Plugin
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return info, fmt.Errorf("failed to open ZIP file: %v", err)
	}
	defer r.Close()

	if err := validatePluginArchive(r.File); err != nil {
		return info, err
	}

	var manifest *zip.File
	for _, f := range r.File {
		if f.Name == manifestFile {
			manifest = f
			break
		}
	}
	if manifest == nil {
		return info, fmt.Errorf("plugin manifest %s not found, not a valid plugin package", manifestFile)
	}

	rc, err := manifest.Open()
	if err != nil {
		return info, fmt.Errorf("failed to read plugin manifest: %v", err)
	}
	configData, readErr := io.ReadAll(io.LimitReader(rc, maxPluginManifestSize+1))
	_ = rc.Close()
	if readErr != nil {
		return info, fmt.Errorf("failed to read plugin manifest: %v", readErr)
	}
	if len(configData) > maxPluginManifestSize {
		return info, fmt.Errorf("plugin manifest exceeds the %d byte limit", maxPluginManifestSize)
	}
	if err := json.Unmarshal(configData, &info); err != nil {
		return info, fmt.Errorf("invalid plugin manifest: %v", err)
	}
	if err := validateManifest(&info); err != nil {
		return info, err
	}
	if err := CheckKomariVersion(info.Komari); err != nil {
		return info, err
	}

	// 1. 在 DataDir 内的独立暂存目录解压并校验。此时完全不触碰已安装版本，
	//    也不会执行包内代码。
	if err := os.MkdirAll(pluginWorkRoot(), 0755); err != nil {
		return info, fmt.Errorf("failed to create plugin staging root: %v", err)
	}
	staging, err := os.MkdirTemp(pluginWorkRoot(), "staging-"+info.Short+"-")
	if err != nil {
		return info, fmt.Errorf("failed to create plugin staging directory: %v", err)
	}
	defer os.RemoveAll(staging)
	if err := extractPluginArchive(r.File, staging); err != nil {
		return info, err
	}
	if err := validateStagedPlugin(staging, info); err != nil {
		return info, err
	}

	// 2. 校验通过后切换。同一插件的切换串行化，避免回滚与另一次更新交错。
	unlock := lockInstall(info.Short)
	defer unlock()

	dir := filepath.Join(DataDir, info.Short)
	previous := global.stateStore().get(info.Short)
	if err := global.unload(info.Short); err != nil && !errors.Is(err, errNotLoaded) {
		return info, fmt.Errorf("failed to unload running plugin %q before reinstall: %w", info.Short, err)
	}

	backupDir, haveBackup, err := movePluginAside(dir, info.Short)
	if err != nil {
		return info, err
	}
	activateErr := error(nil)
	if installActivateHook != nil {
		activateErr = installActivateHook(staging, dir)
	}
	if activateErr == nil {
		activateErr = os.Rename(staging, dir)
	}
	if activateErr != nil {
		// 切换失败：恢复旧版本目录与启用状态，旧插件仍在磁盘上。
		restoreErr := restorePreviousPlugin(dir, backupDir, haveBackup, info.Short, previous)
		if restoreErr != nil {
			return info, fmt.Errorf("failed to activate the new plugin version (%v) and restoring the previous version failed: %v", activateErr, restoreErr)
		}
		return info, fmt.Errorf("failed to activate the new plugin version: %v", activateErr)
	}

	// 3. 只有启用过的插件需要重新加载；加载失败也回滚到旧版本。
	if previous.Enabled {
		if err := global.restartPlugin(info.Short); err != nil {
			restoreErr := restorePreviousPlugin(dir, backupDir, haveBackup, info.Short, previous)
			if restoreErr != nil {
				return info, fmt.Errorf("plugin update could not be loaded (%v) and restoring the previous version failed: %v", err, restoreErr)
			}
			return info, fmt.Errorf("plugin update was not loaded; the previous version was restored: %w", err)
		}
	}
	if haveBackup {
		_ = os.RemoveAll(backupDir)
	}
	return info, nil
}

// pluginWorkRoot is the hidden directory inside DataDir used for staging and
// rollback. Its entries carry no manifest, so plugin listing and startup load
// skip them.
func pluginWorkRoot() string {
	return filepath.Join(DataDir, ".komari-plugin-work")
}

// validateStagedPlugin checks the files the manifest declares inside the
// staging directory. Only file existence is inspected: validating a package
// must never execute its code.
func validateStagedPlugin(staging string, info models.Plugin) error {
	if _, err := os.Stat(filepath.Join(staging, info.Entry)); err != nil {
		return fmt.Errorf("plugin entry %s does not exist", info.Entry)
	}
	for _, page := range info.Pages {
		if page.Type != models.PageTypeIframe {
			continue
		}
		if _, err := os.Stat(filepath.Join(staging, page.File)); err != nil {
			return fmt.Errorf("plugin page %s does not exist", page.File)
		}
	}
	return nil
}

// movePluginAside renames the currently installed directory into the work
// root. The rename stays inside DataDir, so it works when DataDir is a mount
// point and never deletes the old version.
func movePluginAside(dir, short string) (string, bool, error) {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to inspect plugin directory: %v", err)
	}
	backupDir := filepath.Join(pluginWorkRoot(), fmt.Sprintf("previous-%s-%d", short, time.Now().UnixNano()))
	if err := os.Rename(dir, backupDir); err != nil {
		return "", false, fmt.Errorf("failed to move the current plugin version aside: %v", err)
	}
	return backupDir, true, nil
}

// restorePreviousPlugin puts the previous version back and reloads it when it
// was enabled. With no previous version the partially installed package is
// removed so a failed first install leaves nothing behind.
func restorePreviousPlugin(dir, backupDir string, haveBackup bool, short string, previous PluginState) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove the new plugin version: %v", err)
	}
	if !haveBackup {
		return nil
	}
	if err := os.Rename(backupDir, dir); err != nil {
		return fmt.Errorf("failed to restore the previous plugin version: %v", err)
	}
	if previous.Enabled {
		if err := global.restartPlugin(short); err != nil {
			return fmt.Errorf("failed to reload the previous plugin version: %v", err)
		}
	}
	return nil
}

func validatePluginArchive(files []*zip.File) error {
	if len(files) > maxPluginArchiveFiles {
		return fmt.Errorf("plugin archive has more than %d files", maxPluginArchiveFiles)
	}
	var total uint64
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		if file.UncompressedSize64 > maxPluginFileSize {
			return fmt.Errorf("plugin file %s exceeds the %d byte limit", file.Name, maxPluginFileSize)
		}
		total += file.UncompressedSize64
		if total > maxPluginExtractedSize {
			return fmt.Errorf("plugin archive exceeds the %d byte extraction limit", maxPluginExtractedSize)
		}
	}
	return nil
}

func extractPluginArchive(files []*zip.File, dir string) error {
	for _, f := range files {
		path := filepath.Join(dir, f.Name)
		if !withinDir(path, dir) {
			return fmt.Errorf("plugin archive contains an invalid path %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %v", err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open archive file: %v", err)
		}
		outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			_ = rc.Close()
			return fmt.Errorf("failed to create file: %v", err)
		}
		_, copyErr := io.Copy(outFile, rc)
		_ = outFile.Close()
		_ = rc.Close()
		if copyErr != nil {
			return fmt.Errorf("failed to extract file: %v", copyErr)
		}
	}
	return nil
}

// withinDir reports whether path stays inside dir after cleaning.
func withinDir(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}
