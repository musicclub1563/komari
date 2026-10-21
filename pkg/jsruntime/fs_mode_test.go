package jsruntime

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Regression test for fs.writeFileSync(path, data, "utf8"): the third argument
// is an encoding, not an options object. It used to be parsed as a file mode,
// which created the file with permission 000 on Unix and made every following
// read fail with EACCES.
func TestNodeWriteFileWithEncodingUsesDefaultMode(t *testing.T) {
	baseDir := t.TempDir()
	jsRuntime, err := New(`
		async function verify() {
			const fs = require("node:fs");
			fs.writeFileSync("encoded.txt", "encoded", "utf8");
			const text = fs.readFileSync("encoded.txt", "utf8");
			if (text !== "encoded") {
				throw new Error("unexpected content: " + text);
			}
			fs.appendFileSync("encoded.txt", "-more", "utf8");
			if (fs.readFileSync("encoded.txt", "utf8") !== "encoded-more") {
				throw new Error("append failed");
			}
			return true;
		}
	`, Options{NodeJS: true, BaseDir: baseDir, Console: io.Discard, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer jsRuntime.Close()

	if err := jsRuntime.Call("verify"); err != nil {
		t.Fatalf("write file with encoding option failed: %v", err)
	}

	info, err := os.Stat(filepath.Join(baseDir, "encoded.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() == 0 {
		t.Fatalf("file created with permission 000, mode=%v", info.Mode())
	}
}
