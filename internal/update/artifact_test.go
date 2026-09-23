package update

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func TestSignVerifyCacheApplyRollback(t *testing.T) {
	pub, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(pub, ComponentAgent, "1.1.0", runtime.GOOS, runtime.GOARCH, []byte("agent-v1.1"), time.Hour, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, pub.Public.NodeID, time.Time{}, true); err != nil {
		t.Fatal(err)
	}
	wrong, _ := identity.Generate()
	if err := Verify(env, wrong.Public.NodeID, time.Time{}, true); err == nil {
		t.Fatal("wrong publisher")
	}
	st := store.NewMemory()
	c := Cache{Store: st}
	if err := c.Put(env); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.Get(ComponentAgent, "1.1.0", runtime.GOOS, runtime.GOARCH)
	if err != nil || !ok || string(got.Payload) != "agent-v1.1" {
		t.Fatalf("%+v %v %v", got, ok, err)
	}

	dir := t.TempDir()
	current := filepath.Join(dir, string(ComponentAgent))
	if runtime.GOOS == "windows" {
		current += ".exe"
	}
	if err := os.WriteFile(current, []byte("agent-v1.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := Stage(dir, env, "1.0.0", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(plan.Current)
	if string(body) != "agent-v1.1" {
		t.Fatalf("%s", body)
	}
	if err := Rollback(plan); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(plan.Current)
	if string(body) != "agent-v1.0" {
		t.Fatalf("rollback %s", body)
	}
	if err := Receipt(st, env.Artifact, "succeeded", "applied and rolled back in test"); err != nil {
		t.Fatal(err)
	}
}

func TestPeerCannotIntroduceUntrusted(t *testing.T) {
	publisher, _ := identity.Generate()
	peer, _ := identity.Generate()
	env, _ := Sign(peer, ComponentAgent, "9.0.0", runtime.GOOS, runtime.GOARCH, []byte("evil"), time.Hour, "mesh")
	c := Cache{Store: store.NewMemory()}
	if err := AcceptFromPeer(c, env, publisher.Public.NodeID); err == nil {
		t.Fatal("untrusted publisher via mesh")
	}
	good, _ := Sign(publisher, ComponentAgent, "1.2.0", runtime.GOOS, runtime.GOARCH, []byte("ok"), time.Hour, "mesh")
	if err := AcceptFromPeer(c, good, publisher.Public.NodeID); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredAndVersionPolicy(t *testing.T) {
	pub, _ := identity.Generate()
	env, _ := Sign(pub, ComponentConsole, "1.0.0", runtime.GOOS, runtime.GOARCH, []byte("c"), time.Millisecond, "local")
	time.Sleep(5 * time.Millisecond)
	if err := Verify(env, pub.Public.NodeID, time.Now().UTC(), false); err == nil {
		t.Fatal("expired")
	}
	if err := AllowVersion("1.2.0", "1.1.0", false); err == nil {
		t.Fatal("downgrade")
	}
	if err := AllowVersion("1.2.0", "1.1.0", true); err != nil {
		t.Fatal(err)
	}
}

func TestCacheForeignOSArtifact(t *testing.T) {
	pub, _ := identity.Generate()
	env, err := Sign(pub, ComponentAgent, "2.0.0", "windows", "amd64", []byte("win-agent"), time.Hour, "github")
	if err != nil {
		t.Fatal(err)
	}
	c := Cache{Store: store.NewMemory()}
	if err := AcceptFromPeer(c, env, pub.Public.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(t.TempDir(), env, "1.0.0", false); err == nil && runtime.GOOS != "windows" {
		t.Fatal("must not apply windows artifact on this os")
	}
}

func TestWrongArchRejected(t *testing.T) {
	pub, _ := identity.Generate()
	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	env, _ := Sign(pub, ComponentAgent, "1.0.0", runtime.GOOS, otherArch, []byte("x"), time.Hour, "github")
	if err := Verify(env, pub.Public.NodeID, time.Time{}, true); err == nil {
		t.Fatal("wrong arch")
	}
}
