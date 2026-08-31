package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocsContracts(t *testing.T) {
	root := repoRoot(t)
	mustContain := map[string][]string{
		"docs/ARCHITECTURE.md": {
			"queued → routed → received → validated → applying → succeeded|failed → acknowledged",
			"rmm/v1/",
			"interop/mgmt/v1/",
			"Discovery",
			"Badger",
		},
		"docs/THREAT_MODEL.md": {
			"Discovery grants nothing",
			"No unauthenticated public desktop listener",
			"never persist",
			"command.run",
		},
		"docs/PROTOCOL.md": {
			"rmm-hello-v1",
			"XChaCha20-Poly1305",
			"untrusted_peer",
		},
		"docs/REMOTE_DESKTOP.md": {
			"authorization-required",
			"unattended",
			"ephemeral",
			"X11",
			"Wayland",
			"direct local access",
		},
		"docs/INTEROP.md": {
			"Discovery grants nothing",
			"fse/v1/",
			"file/block",
		},
		"docs/STACK_DECISION.md": {
			"Go 1.22",
			"BadgerDB",
			"Windows 10",
			"CGO_ENABLED=0",
		},
	}
	for rel, needles := range mustContain {
		body := read(t, filepath.Join(root, rel))
		for _, n := range needles {
			if !strings.Contains(body, n) {
				t.Errorf("%s missing %q", rel, n)
			}
		}
	}
}

func TestArchiveNotice(t *testing.T) {
	body := read(t, filepath.Join(repoRoot(t), "archive/dotnet-windows-service/NOTICE.md"))
	for _, n := range []string{"rqlite", "rhinodht", "IPFS", "not part of the product"} {
		if !strings.Contains(body, n) {
			t.Errorf("archive notice missing %q", n)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found")
	return ""
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
