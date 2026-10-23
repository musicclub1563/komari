package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	// v1/v2 使用同一组权限，更新后无需重新审批；v2NewPerm 额外申请权限，
	// 用于构造“加载失败”场景。
	v1Manifest        = `{"name":"Demo","short":"demo","version":"1.0.0","komari":">=0.0.1","permissions":{"allowHTMLInject":true,"timeout":5}}`
	v2Manifest        = `{"name":"Demo","short":"demo","version":"2.0.0","komari":">=0.0.1","permissions":{"allowHTMLInject":true,"timeout":5}}`
	v2NewPermManifest = `{"name":"Demo","short":"demo","version":"2.0.0","komari":">=0.0.1","permissions":{"allowHTMLInject":true,"allowSystemRPC":true,"timeout":5}}`
	v1Script          = `function load() {} // v1`
	v2Script          = `function load() {} // v2`
)

func installDemoV1(t *testing.T) {
	t.Helper()
	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": v1Manifest,
		"script.js":          v1Script,
	})
	if _, err := InstallZip(zipPath); err != nil {
		t.Fatalf("install v1: %v", err)
	}
}

func requirePluginFile(t *testing.T, rel, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(DataDir, "demo", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", rel, string(data), want)
	}
}

func requireManifestVersion(t *testing.T, want string) {
	t.Helper()
	info, err := readManifest(filepath.Join(DataDir, "demo"))
	if err != nil {
		t.Fatalf("read installed manifest: %v", err)
	}
	if info.Version != want {
		t.Fatalf("installed version = %q, want %q", info.Version, want)
	}
}

// TestUpdateKeepsOldVersionWhenEntryMissing reproduces the reported bug: an
// update package without script.js must not delete the installed script.
func TestUpdateKeepsOldVersionWhenEntryMissing(t *testing.T) {
	withTempDataDir(t)
	installDemoV1(t)

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": v2Manifest,
	})
	if _, err := InstallZip(zipPath); err == nil {
		t.Fatal("expected the update without script.js to fail")
	}
	requirePluginFile(t, "script.js", v1Script)
	requireManifestVersion(t, "1.0.0")
}

func TestUpdateKeepsOldVersionForTraversal(t *testing.T) {
	withTempDataDir(t)
	installDemoV1(t)

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": v2Manifest,
		"script.js":          v2Script,
		"../evil.txt":        "boom",
	})
	if _, err := InstallZip(zipPath); err == nil {
		t.Fatal("expected the traversal package to be rejected")
	}
	requirePluginFile(t, "script.js", v1Script)
	if _, err := os.Stat(filepath.Join(DataDir, "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("traversal escaped the plugin directory")
	}
}

func TestUpdateKeepsOldVersionForCorruptArchive(t *testing.T) {
	withTempDataDir(t)
	installDemoV1(t)

	broken := filepath.Join(t.TempDir(), "broken.zip")
	if err := os.WriteFile(broken, []byte("not a zip archive"), 0644); err != nil {
		t.Fatalf("write broken archive: %v", err)
	}
	if _, err := InstallZip(broken); err == nil {
		t.Fatal("expected the corrupt archive to be rejected")
	}
	requirePluginFile(t, "script.js", v1Script)
	requireManifestVersion(t, "1.0.0")
}

func TestUpdateKeepsOldVersionWhenPageMissing(t *testing.T) {
	withTempDataDir(t)
	installDemoV1(t)

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": `{"name":"Demo","short":"demo","version":"2.0.0","komari":">=0.0.1","pages":[{"file":"admin.html","title":"Admin"}],"permissions":{"allowHTMLInject":true}}`,
		"script.js":          v2Script,
	})
	if _, err := InstallZip(zipPath); err == nil {
		t.Fatal("expected the missing page file to be rejected")
	}
	requirePluginFile(t, "script.js", v1Script)
	requireManifestVersion(t, "1.0.0")
}

// TestUpdateRollsBackWhenReloadFails covers a package that installs cleanly but
// cannot be loaded: the declared permissions changed, so the stored approval no
// longer matches. The previous version and its enabled state must come back.
func TestUpdateRollsBackWhenReloadFails(t *testing.T) {
	withTempDataDir(t)
	installDemoV1(t)
	if err := SetEnabled("demo", true, true); err != nil {
		t.Fatalf("enable v1: %v", err)
	}
	t.Cleanup(func() { _ = SetEnabled("demo", false, false) })

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": v2NewPermManifest,
		"script.js":          v2Script,
	})
	_, err := InstallZip(zipPath)
	if err == nil {
		t.Fatal("expected the update to fail without a new permission approval")
	}
	if !strings.Contains(err.Error(), "approval") {
		t.Fatalf("error = %v, want an approval error", err)
	}

	requirePluginFile(t, "script.js", v1Script)
	requireManifestVersion(t, "1.0.0")
	state := global.stateStore().get("demo")
	if !state.Enabled {
		t.Fatal("plugin was not restored to its enabled state")
	}
	if state.LastError != "" {
		t.Fatalf("restored plugin keeps an error: %q", state.LastError)
	}
	if global.instanceFor("demo") == nil {
		t.Fatal("previous version was not reloaded after the rollback")
	}
}

// TestUpdateRollsBackWhenActivationFails injects a failure in the swap itself.
func TestUpdateRollsBackWhenActivationFails(t *testing.T) {
	withTempDataDir(t)
	installDemoV1(t)

	installActivateHook = func(string, string) error { return os.ErrPermission }
	t.Cleanup(func() { installActivateHook = nil })

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": v2Manifest,
		"script.js":          v2Script,
	})
	if _, err := InstallZip(zipPath); err == nil {
		t.Fatal("expected the activation failure to be reported")
	}
	requirePluginFile(t, "script.js", v1Script)
	requireManifestVersion(t, "1.0.0")
}

func TestUpdateSucceedsAndClearsStaging(t *testing.T) {
	withTempDataDir(t)
	installDemoV1(t)

	zipPath := writePluginZip(t, map[string]string{
		"komari-plugin.json": v2Manifest,
		"script.js":          v2Script,
	})
	if _, err := InstallZip(zipPath); err != nil {
		t.Fatalf("valid update failed: %v", err)
	}
	requirePluginFile(t, "script.js", v2Script)
	requireManifestVersion(t, "2.0.0")

	entries, err := os.ReadDir(pluginWorkRoot())
	if err != nil {
		t.Fatalf("read work root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging/rollback leftovers: %d entries", len(entries))
	}
}

// TestConcurrentUpdatesOfSamePlugin verifies that two simultaneous updates of
// the same plugin do not corrupt the installation: the swap is serialized and
// the result is a complete, loadable package.
func TestConcurrentUpdatesOfSamePlugin(t *testing.T) {
	withTempDataDir(t)
	installDemoV1(t)

	updated := []string{v2Script, `function load() {} // v2-alt`}
	// Packages are built before the goroutines start: test helpers must not
	// call t.Fatal from a non-test goroutine.
	archives := make([]string, len(updated))
	for index, script := range updated {
		archives[index] = writePluginZip(t, map[string]string{
			"komari-plugin.json": v2Manifest,
			"script.js":          script,
		})
	}

	var wg sync.WaitGroup
	errs := make([]error, len(archives))
	for index, archive := range archives {
		wg.Add(1)
		go func(index int, archive string) {
			defer wg.Done()
			_, errs[index] = InstallZip(archive)
		}(index, archive)
	}
	wg.Wait()

	for index, err := range errs {
		if err != nil {
			t.Fatalf("concurrent update %d failed: %v", index, err)
		}
	}
	requireManifestVersion(t, "2.0.0")
	data, err := os.ReadFile(filepath.Join(DataDir, "demo", "script.js"))
	if err != nil {
		t.Fatalf("read script after concurrent updates: %v", err)
	}
	content := string(data)
	if content != v2Script && content != `function load() {} // v2-alt` {
		t.Fatalf("script.js = %q, want one of the two updates", content)
	}
}
