package consolemesh

import (
	"context"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/localpeer"
	"github.com/bstone108/Decentralized-RMM/internal/node"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

func TestPrefersLocalTrustedAgent(t *testing.T) {
	dir := t.TempDir()
	agentStore := store.NewMemory()
	consoleStore := store.NewMemory()
	agent, err := node.Open(agentStore, node.RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	console, err := node.Open(consoleStore, node.RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Pair(trust.Offer(console.ID, "console")); err != nil {
		t.Fatal(err)
	}
	if err := console.Pair(trust.Offer(agent.ID, "agent")); err != nil {
		t.Fatal(err)
	}
	agent.SetPresenceDir(dir)
	addr, err := agent.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	adv, ok, err := localpeer.Read(dir)
	if err != nil || !ok || adv.ListenAddr != addr {
		t.Fatalf("agent must advertise local mesh presence: %+v %v %v", adv, ok, err)
	}
	rt, err := Start(console, dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if rt.Mode != ModeViaLocalAgent || rt.LocalAddr != addr {
		t.Fatalf("%+v", rt)
	}
	if console.HasListener() {
		t.Fatal("console must not start its own mesh listener when a local agent is reused")
	}
}

func TestBuiltinMeshWhenNoLocalAgent(t *testing.T) {
	st := store.NewMemory()
	c, err := node.Open(st, node.RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := Start(c, t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if rt.Mode != ModeBuiltin || rt.MeshAddr == "" {
		t.Fatalf("%+v", rt)
	}
}

func TestConsoleRefusesAgentApply(t *testing.T) {
	st := store.NewMemory()
	c, err := node.Open(st, node.RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := identity.Generate()
	in := intent.New("x", "x", other.Public.NodeID, c.ID.Public.NodeID, intent.KindInventoryCollect, nil)
	if _, _, err := c.HandleIntent(in); err == nil {
		t.Fatal("console must not apply endpoint-management intents")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = ctx
}

func TestDualRoleWithdrawn(t *testing.T) {
	if _, err := node.Open(store.NewMemory(), node.RoleDual, nil); err == nil {
		t.Fatal("dual withdrawn")
	}
}
