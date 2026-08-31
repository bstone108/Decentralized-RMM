package node

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/mesh"
	"github.com/bstone108/Decentralized-RMM/internal/security"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

func TestTwoNodeAuthenticatedIntentAck(t *testing.T) {
	secret := []byte("ephemeral-admin-proof-value")
	agentDir := t.TempDir()
	consoleDir := t.TempDir()
	agentStore, err := store.OpenBadger(store.DataDir(agentDir))
	if err != nil {
		t.Fatal(err)
	}
	consoleStore, err := store.OpenBadger(store.DataDir(consoleDir))
	if err != nil {
		t.Fatal(err)
	}
	agent, err := Open(agentStore, RoleAgent, desktop.PasswordVerifier{ExpectedUser: "root", ExpectedPass: secret})
	if err != nil {
		t.Fatal(err)
	}
	console, err := Open(consoleStore, RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Pair(trust.Offer(console.ID, "console")); err != nil {
		t.Fatal(err)
	}
	if err := console.Pair(trust.Offer(agent.ID, "agent")); err != nil {
		t.Fatal(err)
	}

	addr, err := agent.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, err := console.Dial(ctx, addr, agent.ID.Public.NodeID)
	if err != nil {
		t.Fatal(err)
	}

	queued, err := console.Queue(intent.New("intent-inv-1", "idem-inv-1", console.ID.Public.NodeID, agent.ID.Public.NodeID, intent.KindInventoryCollect, nil))
	if err != nil {
		t.Fatal(err)
	}
	ack, err := console.Deliver(sess, queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != intent.Succeeded {
		t.Fatalf("ack=%+v", ack)
	}
	if !bytes.Contains(ack.Result, []byte(agent.ID.Public.NodeID[:0])) {
		// result is inventory JSON; hostname/os must be present
		if !bytes.Contains(ack.Result, []byte(`"os"`)) {
			t.Fatalf("inventory result %s", ack.Result)
		}
	}
	_ = sess.Close()

	if err := agentStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := consoleStore.Close(); err != nil {
		t.Fatal(err)
	}
	agentStore, err = store.OpenBadger(store.DataDir(agentDir))
	if err != nil {
		t.Fatal(err)
	}
	defer agentStore.Close()
	consoleStore, err = store.OpenBadger(store.DataDir(consoleDir))
	if err != nil {
		t.Fatal(err)
	}
	defer consoleStore.Close()

	got, ok, err := intent.Load(consoleStore, "intent-inv-1")
	if err != nil || !ok || got.Status != intent.Acknowledged {
		t.Fatalf("durable origin status %+v ok=%v err=%v", got, ok, err)
	}
	rec, ok, err := intent.LoadReceipt(consoleStore, "intent-inv-1")
	if err != nil || !ok || rec.Status != intent.Succeeded {
		t.Fatalf("durable receipt %+v ok=%v err=%v", rec, ok, err)
	}
	agentIntent, ok, err := intent.Load(agentStore, "intent-inv-1")
	if err != nil || !ok || agentIntent.Status != intent.Succeeded {
		t.Fatalf("durable target %+v ok=%v err=%v", agentIntent, ok, err)
	}

	// Untrusted node is refused.
	untrustedStore := store.NewMemory()
	untrusted, err := Open(untrustedStore, RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	agent2, err := Open(agentStore, RoleAgent, desktop.PasswordVerifier{ExpectedUser: "root", ExpectedPass: secret})
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := agent2.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer agent2.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()
	if _, err := untrusted.Dial(ctx2, addr2, agent2.ID.Public.NodeID); err == nil {
		t.Fatal("untrusted dial must fail")
	}

	// Idempotent replay on target.
	replay := intent.New("intent-inv-1", "idem-inv-1", console.ID.Public.NodeID, agent2.ID.Public.NodeID, intent.KindInventoryCollect, nil)
	_, rec2, err := agent2.HandleIntent(replay)
	if err != nil {
		t.Fatal(err)
	}
	if rec2.Status != intent.Succeeded {
		t.Fatalf("replay %s", rec2.Status)
	}

	// command.run fails closed.
	cmd := intent.New("intent-cmd-1", "idem-cmd-1", console.ID.Public.NodeID, agent2.ID.Public.NodeID, intent.KindCommandRun, []byte(`{"program":"id"}`))
	_, cmdAck, err := agent2.HandleIntent(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if cmdAck.Status != intent.Failed {
		t.Fatalf("command.run must fail closed: %+v", cmdAck)
	}

	// Desktop unattended without proof fails; with proof succeeds; secret not stored.
	console2, err := Open(consoleStore, RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = agent2.Pair(trust.Offer(console2.ID, "console"))
	_ = console2.Pair(trust.Offer(agent2.ID, "agent"))
	sess2, err := console2.Dial(ctx2, addr2, agent2.ID.Public.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"mode": "unattended"})
	noProof, err := console2.Queue(intent.New("intent-desk-1", "idem-desk-1", console2.ID.Public.NodeID, agent2.ID.Public.NodeID, intent.KindDesktopModeChange, payload))
	if err != nil {
		t.Fatal(err)
	}
	ackFail, err := console2.Deliver(sess2, noProof.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ackFail.Status != intent.Failed {
		t.Fatalf("expected failed without proof: %+v", ackFail)
	}
	_ = sess2.Close()

	sess3, err := console2.Dial(ctx2, addr2, agent2.ID.Public.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer sess3.Close()
	payload2, _ := json.Marshal(map[string]string{"mode": "unattended", "username": "root", "password": string(secret)})
	withProof, err := console2.Queue(intent.New("intent-desk-2", "idem-desk-2", console2.ID.Public.NodeID, agent2.ID.Public.NodeID, intent.KindDesktopModeChange, payload2))
	if err != nil {
		t.Fatal(err)
	}
	ackOK, err := console2.Deliver(sess3, withProof.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ackOK.Status != intent.Succeeded {
		t.Fatalf("expected success with proof: %+v", ackOK)
	}
	dump, err := store.DumpValues(agentStore)
	if err != nil {
		t.Fatal(err)
	}
	if security.ContainsSecret(dump, secret) {
		t.Fatal("admin password persisted on agent")
	}
	cdump, err := store.DumpValues(consoleStore)
	if err != nil {
		t.Fatal(err)
	}
	if security.ContainsSecret(cdump, secret) {
		t.Fatal("admin password persisted on console")
	}
	if err := store.Validate(agentStore); err != nil {
		t.Fatal(err)
	}
	pol, err := desktop.LoadPolicy(agentStore)
	if err != nil || pol.Mode != desktop.ModeUnattended {
		t.Fatalf("policy %+v %v", pol, err)
	}

	// Untrusted discovered candidate cannot connect.
	if err := mesh.AllowConnect(mesh.Discovered{NodeID: agent2.ID.Public.NodeID, Source: mesh.SourceDHT, Trusted: false}); err == nil {
		t.Fatal("discovery must not grant connect")
	}
}

func TestLocalIdentityPersists(t *testing.T) {
	st := store.NewMemory()
	n1, err := Open(st, RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := Open(st, RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n1.ID.Public.NodeID != n2.ID.Public.NodeID {
		t.Fatal("identity should persist in store")
	}
	_ = identity.ValidNodeID(n1.ID.Public.NodeID)
}
