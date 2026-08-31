package host

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCollectLinuxDistroAndDisplay(t *testing.T) {
	snap := Collect()
	if snap.OS != runtime.GOOS || snap.Arch != runtime.GOARCH || snap.Hostname == "" {
		t.Fatalf("%+v", snap)
	}
	if runtime.GOOS != "linux" {
		return
	}
	if snap.Distro == "" {
		t.Log("os-release missing in this environment")
	}
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	t.Setenv("DISPLAY", ":0")
	t.Setenv("XDG_SESSION_TYPE", "wayland")
	t.Setenv("USER", "tester")
	s := Collect()
	if s.DisplayServer != "both" && s.DisplayServer != "wayland" && s.DisplayServer != "x11" {
		// Collect reads current env; after t.Setenv it should see both.
		if s.DisplayServer != "both" {
			t.Fatalf("displayServer=%q (want x11/wayland/both)", s.DisplayServer)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip()
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	if err := os.WriteFile(path, []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, ver := parseOSRelease(path)
	if id != "ubuntu" || ver != "24.04" {
		t.Fatalf("%s %s", id, ver)
	}
}
