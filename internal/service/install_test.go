package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallForSupportedPlatforms(t *testing.T) {
	for _, test := range []struct {
		goos string
		name string
		want string
	}{
		{"darwin", "com.steermesh.axon.plist", "/bin/a&amp;b"},
		{"linux", "mesh-axon.service", `"/bin/a&b" serve`},
	} {
		t.Run(test.goos, func(t *testing.T) {
			home := t.TempDir()
			path, err := installForOS(test.goos, "/bin/a&b", home)
			if err != nil {
				t.Fatal(err)
			}
			if filepath.Base(path) != test.name {
				t.Fatalf("path=%q", path)
			}
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), test.want) {
				t.Fatalf("content=%q err=%v", data, err)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("mode=%o", info.Mode().Perm())
			}
		})
	}
}

func TestInstallRejectsUnsupportedPlatformAndWriteFailure(t *testing.T) {
	if _, err := installForOS("plan9", "axon", t.TempDir()); err == nil {
		t.Fatal("unsupported platform accepted")
	}
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := write(filepath.Join(parent, "child"), "content"); err == nil {
		t.Fatal("write through regular file succeeded")
	}
	if _, err := write(t.TempDir(), "content"); err == nil {
		t.Fatal("directory was overwritten as a service file")
	}
}

func TestInstallUsesCurrentPlatform(t *testing.T) {
	path, err := Install("/bin/axon", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
