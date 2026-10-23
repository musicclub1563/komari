package plugin

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
)

func TestMain(m *testing.M) {
	flags.DatabaseType = flags.DatabaseTypeSQLite
	flags.DatabaseFile = "file:komari_plugin_test?mode=memory&cache=shared"
	db := dbcore.GetDBInstance()
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	os.Exit(m.Run())
}

// withTempDataDir redirects DataDir and StorageDir and resets the global
// manager for the duration of a test.
func withTempDataDir(t *testing.T) {
	t.Helper()
	oldDir := DataDir
	oldStorage := StorageDir
	oldGlobal := global
	DataDir = t.TempDir()
	StorageDir = t.TempDir()
	mgr := &Manager{
		instances: make(map[string]*Instance),
		routes:    make(map[string]map[string]bool),
		logs:      make(map[string]*LogBuffer),
	}
	global = mgr
	t.Cleanup(func() { _ = mgr.closeAll() }) // release runtimes before TempDir removal
	t.Cleanup(func() {
		DataDir = oldDir
		StorageDir = oldStorage
		global = oldGlobal
	})
}

// resetPluginConfiguration removes persisted plugin configuration so repeated
// runs (-count>1) start from the manifest defaults again.
func resetPluginConfiguration(t *testing.T, shorts ...string) {
	t.Helper()
	if err := dbcore.GetDBInstance().Where("short IN ?", shorts).
		Delete(&models.PluginConfiguration{}).Error; err != nil {
		t.Fatalf("reset plugin configuration: %v", err)
	}
}

// resetSelectorFixture removes the fixed client and ping task rows used by the
// selector configuration tests so repeated runs can create them again.
func resetSelectorFixture(t *testing.T) {
	t.Helper()
	db := dbcore.GetDBInstance()
	if err := db.Where("uuid = ?", "node-a").Delete(&models.Client{}).Error; err != nil {
		t.Fatalf("reset clients: %v", err)
	}
	if err := db.Where("id = ?", 8).Delete(&models.PingTask{}).Error; err != nil {
		t.Fatalf("reset ping tasks: %v", err)
	}
}

// writePluginZip creates a plugin ZIP from a name -> content map.
func writePluginZip(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugin.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
	for name, content := range files {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
