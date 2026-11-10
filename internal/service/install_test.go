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
			path, err := installForOS(test.goos, "/bin/a&b", home, nil)
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
	if _, err := installForOS("plan9", "axon", t.TempDir(), nil); err == nil {
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

func TestInstallForSupportedPlatformsOmitsRelayWhenUnset(t *testing.T) {
	home := t.TempDir()
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			path, err := installForOS(goos, "/bin/axon", home, nil)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			body := string(data)
			if strings.Contains(body, "AXON_RELAY_URL") {
				t.Fatalf("unexpected relay env in %q", body)
			}
		})
	}
}

func TestInstallEmbedsRelayURLWhenSet(t *testing.T) {
	env := map[string]string{"AXON_RELAY_URL": "wss://relay.example/ws"}
	home := t.TempDir()

	t.Run("darwin", func(t *testing.T) {
		path, err := installForOS("darwin", "/bin/axon", home, env)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data)
		for _, want := range []string{
			"<key>EnvironmentVariables</key>",
			"<key>AXON_RELAY_URL</key>",
			"<string>wss://relay.example/ws</string>",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("missing %q in:\n%s", want, body)
			}
		}
	})

	t.Run("linux", func(t *testing.T) {
		path, err := installForOS("linux", "/bin/axon", home, env)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data)
		want := "Environment=AXON_RELAY_URL=wss://relay.example/ws"
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	})
}

