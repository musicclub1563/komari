package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiagRootWrite(t *testing.T) {
	base := t.TempDir()
	m, err := New(nil, base, base, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("base=%q", base)
	dataDir := filepath.Join(base, "data")
	t.Logf("mkdir err=%v", m.nodeMkdir(dataDir, 0o777, true))
	if info, err := os.Stat(dataDir); err == nil {
		t.Logf("data mode=%v perm=%o", info.Mode(), info.Mode().Perm())
	} else {
		t.Logf("stat err=%v", err)
	}
	target := filepath.Join(dataDir, "x.txt")
	if root, rel, unlock, err := m.filesystemFor(target); err != nil {
		t.Logf("filesystemFor err=%v", err)
	} else {
		t.Logf("root=%v relative=%q", root != nil, rel)
		unlock()
	}
	t.Logf("write err=%v", m.nodeWriteFile(target, []byte("x"), 0o666))
	entries, _ := os.ReadDir(base)
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			t.Logf("entry %s mode=%v", e.Name(), info.Mode())
		}
	}
}
