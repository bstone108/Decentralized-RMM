package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func TestDiscoverCacheForeignAndApplyLocal(t *testing.T) {
	pub, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	win, err := Sign(pub, ComponentAgent, "2.0.0", "windows", "amd64", []byte("win-bin"), time.Hour, "github")
	if err != nil {
		t.Fatal(err)
	}
	local, err := Sign(pub, ComponentAgent, "2.0.0", runtime.GOOS, runtime.GOARCH, []byte("local-bin"), time.Hour, "github")
	if err != nil {
		t.Fatal(err)
	}
	winRaw, _ := json.Marshal(win)
	localRaw, _ := json.Marshal(local)
	src := MemorySource{
		Assets: map[string][]byte{"win": winRaw, "local": localRaw},
		ListFn: func() []RemoteAsset {
			return []RemoteAsset{
				{Name: "rmm-agent-windows-amd64.rmm-artifact", URL: "win", Component: ComponentAgent, GOOS: "windows", GOARCH: "amd64"},
				{Name: "rmm-agent-" + runtime.GOOS + "-" + runtime.GOARCH + ".rmm-artifact", URL: "local", Component: ComponentAgent, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH},
			}
		},
	}
	st := store.NewMemory()
	c := Cache{Store: st}
	cached, err := DiscoverAndCache(context.Background(), src, c, pub.Public.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) != 2 {
		t.Fatalf("%d", len(cached))
	}
	dir := t.TempDir()
	current := filepath.Join(dir, string(ComponentAgent))
	if runtime.GOOS == "windows" {
		current += ".exe"
	}
	if err := os.WriteFile(current, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, restart, err := ApplyLocal(st, dir, local, Policy{
		Enabled:          true,
		TrustedPublisher: pub.Public.NodeID,
		CurrentVersion:   "1.0.0",
		Component:        ComponentAgent,
		Adapter:          NativeAdapter(),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(plan.Current)
	if string(body) != "local-bin" {
		t.Fatalf("%s", body)
	}
	if !restart.Relisten || len(restart.Commands) == 0 {
		t.Fatalf("%+v", restart)
	}
	if _, _, err := ApplyLocal(st, dir, win, Policy{Enabled: true, TrustedPublisher: pub.Public.NodeID, CurrentVersion: "1.0.0"}); err == nil && runtime.GOOS != "windows" {
		t.Fatal("must not apply foreign os")
	}
	if err := Recover(plan, st); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(plan.Current)
	if string(body) != "old" {
		t.Fatalf("rollback %s", body)
	}
}

func TestDisabledPolicyAndParseAssetName(t *testing.T) {
	pub, _ := identity.Generate()
	env, _ := Sign(pub, ComponentConsole, "1.0.0", runtime.GOOS, runtime.GOARCH, []byte("c"), time.Hour, "github")
	if _, _, err := ApplyLocal(store.NewMemory(), t.TempDir(), env, Policy{Enabled: false, TrustedPublisher: pub.Public.NodeID}); err == nil {
		t.Fatal("policy")
	}
	comp, goos, goarch, ok := parseAssetName("rmm-agent-linux-amd64")
	if !ok || comp != ComponentAgent || goos != "linux" || goarch != "amd64" {
		t.Fatal(comp, goos, goarch, ok)
	}
}

func TestPeerCannotBypassDiscoverPublisher(t *testing.T) {
	good, _ := identity.Generate()
	evil, _ := identity.Generate()
	env, _ := Sign(evil, ComponentAgent, "9.0.0", runtime.GOOS, runtime.GOARCH, []byte("x"), time.Hour, "github")
	raw, _ := json.Marshal(env)
	_, err := Ingest(Cache{Store: store.NewMemory()}, raw, good.Public.NodeID)
	if err == nil {
		t.Fatal("untrusted")
	}
}
