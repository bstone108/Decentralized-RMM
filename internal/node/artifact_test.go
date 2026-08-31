package node

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/localpeer"
	"github.com/bstone108/Decentralized-RMM/internal/protocol"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
	"github.com/bstone108/Decentralized-RMM/internal/update"
)

func TestAgentAdvertisesAndRemovesLocalPresence(t *testing.T) {
	dir := t.TempDir()
	st := store.NewMemory()
	n, err := Open(st, RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.SetPresenceDir(dir)
	addr, err := n.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adv, ok, err := localpeer.Read(dir)
	if err != nil || !ok || adv.ListenAddr != addr || adv.Role != "agent" {
		t.Fatalf("%+v %v %v", adv, ok, err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := localpeer.Read(dir); err != nil || ok {
		t.Fatal("advertisement must be removed on close")
	}
}

func TestConsoleDoesNotAdvertise(t *testing.T) {
	dir := t.TempDir()
	n, err := Open(store.NewMemory(), RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.SetPresenceDir(dir)
	if _, err := n.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if _, ok, err := localpeer.Read(dir); err != nil || ok {
		t.Fatal("console must not advertise as a local agent")
	}
}

func TestMeshArtifactExchangeIndependentVerify(t *testing.T) {
	publisher, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	holderStore := store.NewMemory()
	recvStore := store.NewMemory()
	holder, err := Open(holderStore, RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := Open(recvStore, RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Pair(trust.Offer(recv.ID, "agent")); err != nil {
		t.Fatal(err)
	}
	if err := recv.Pair(trust.Offer(holder.ID, "agent")); err != nil {
		t.Fatal(err)
	}
	win, err := update.Sign(publisher, update.ComponentAgent, "3.0.0", "windows", "amd64", []byte("win-payload"), time.Hour, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := update.AcceptFromPeer(holder.UpdateCache(), win, publisher.Public.NodeID); err != nil {
		t.Fatal(err)
	}
	addr, err := holder.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := recv.Dial(ctx, addr, holder.ID.Public.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := recv.PullArtifact(sess, protocol.ArtifactRequest{
		Component: string(update.ComponentAgent), Version: "3.0.0", GOOS: "windows", GOARCH: "amd64",
	}, publisher.Public.NodeID); err != nil {
		t.Fatal(err)
	}
	got, ok, err := recv.UpdateCache().Get(update.ComponentAgent, "3.0.0", "windows", "amd64")
	if err != nil || !ok || string(got.Payload) != "win-payload" {
		t.Fatalf("foreign os artifact must be cacheable: %+v %v %v", got, ok, err)
	}

	evil, _ := identity.Generate()
	bad, _ := update.Sign(evil, update.ComponentAgent, "9.9.9", "linux", "amd64", []byte("nope"), time.Hour, "mesh")
	if err := update.AcceptFromPeer(recv.UpdateCache(), bad, publisher.Public.NodeID); err == nil {
		t.Fatal("peers cannot introduce untrusted updates")
	}
}

func TestEnrollFromDirOnAgent(t *testing.T) {
	issuer, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := enroll.Issue(issuer, enroll.Spec{
		OrgID: "acme", TargetOS: nil, TargetArch: nil, MaxUses: 1,
		AllowedCIDRs:   []string{"10.0.0.0/8"},
		BootstrapPeers: []enroll.BootstrapPeer{{NodeID: issuer.Public.NodeID, Address: "10.0.0.2:7946", Kind: "configured"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	raw, err := json.MarshalIndent(bundle.Manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enroll.ManifestFile(dir), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enroll.TokenFile(dir), []byte(enroll.TokenEncode(bundle.Token)), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := Open(store.NewMemory(), RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	man, applied, err := n.EnrollFromDir(dir)
	if err != nil || !applied || man.Scope.OrgID != "acme" {
		t.Fatalf("%+v %v %v", man, applied, err)
	}
	pub, ok, err := enroll.LoadPublisher(n.Store)
	if err != nil || !ok || pub != issuer.Public.NodeID {
		t.Fatal(pub, ok, err)
	}
}

func TestSignedMeshRevocationPreventsEnrollment(t *testing.T) {
	issuerStore := store.NewMemory()
	agentStore := store.NewMemory()
	console, err := Open(issuerStore, RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := Open(agentStore, RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Pair(trust.Offer(console.ID, "console")); err != nil {
		t.Fatal(err)
	}
	if err := console.Pair(trust.Offer(agent.ID, "agent")); err != nil {
		t.Fatal(err)
	}
	bundle, err := enroll.Issue(console.ID, enroll.Spec{
		OrgID: "acme", AllowedUses: enroll.AllowedUses{Mode: enroll.UseUnlimited},
		AllowedCIDRs:   []string{"10.0.0.0/8"},
		BootstrapPeers: []enroll.BootstrapPeer{{NodeID: console.ID.Public.NodeID, Address: "10.0.0.2:1", Kind: "configured"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := enroll.RegisterGrant(issuerStore, bundle.Manifest); err != nil {
		t.Fatal(err)
	}
	notice, err := console.RevokeGrant(bundle.Manifest.Grant(), enroll.ReasonRevoked)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := agent.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := console.Dial(ctx, addr, agent.ID.Public.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := console.PublishRevocation(sess, notice); err != nil {
		t.Fatal(err)
	}
	if _, err := enroll.ConsumeFor(agentStore, agent.Trust, bundle.Manifest, bundle.Token, agent.ID.Public.NodeID); err == nil {
		t.Fatal("revoked grant must not enroll after signed mesh publication")
	}
	if ok, _ := enroll.IsRevoked(agentStore, bundle.Manifest.Grant()); !ok {
		t.Fatal("agent must retain revocation notice")
	}
}
