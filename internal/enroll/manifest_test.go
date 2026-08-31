package enroll

import (
	"bytes"
	"runtime"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

func testSpec() Spec {
	return Spec{
		OrgID:        "acme",
		TargetOS:     []string{runtime.GOOS},
		TargetArch:   []string{runtime.GOARCH},
		MaxUses:      1,
		TTL:          time.Hour,
		RevocationID: "rev-1",
		BootstrapPeers: []BootstrapPeer{{
			NodeID: "rmm1:console", Address: "10.1.2.3:7946", Kind: "configured",
		}},
		AllowedCIDRs: []string{"10.0.0.0/8"},
		DesktopMode:  desktop.ModeAuthorizationRequired,
		SelfUpdate:   true,
	}
}

func TestIssueVerifyConsumeOnce(t *testing.T) {
	issuer, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Issue(issuer, testSpec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bundle.Manifest); err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	book := trust.New(st)
	if err := Consume(st, book, bundle.Manifest, bundle.Token); err != nil {
		t.Fatal(err)
	}
	if err := Consume(st, book, bundle.Manifest, bundle.Token); err == nil {
		t.Fatal("one-time enrollment must not reuse")
	}
	dump, _ := store.DumpValues(st)
	if bytes.Contains(dump, bundle.Token) {
		t.Fatal("raw enrollment token must not be stored")
	}
	if bytes.Contains(dump, []byte(issuer.SeedBase64())) {
		t.Fatal("issuer private key must not be stored from enrollment")
	}
	pol, err := desktop.LoadPolicy(st)
	if err != nil || pol.Mode != desktop.ModeAuthorizationRequired || !pol.InstallAskedOperator {
		t.Fatalf("%+v %v", pol, err)
	}
	ok, err := book.Trusted(issuer.Public.NodeID)
	if err != nil || !ok {
		t.Fatal("issuer must be trusted after enrollment")
	}
}

func TestRejectUnrestrictedNetworkAndPrivateMaterial(t *testing.T) {
	issuer, _ := identity.Generate()
	spec := testSpec()
	spec.AllowedCIDRs = []string{"0.0.0.0/0"}
	if _, err := Issue(issuer, spec); err == nil {
		t.Fatal("unrestricted CIDR")
	}
	spec.AllowedCIDRs = nil
	if _, err := Issue(issuer, spec); err == nil {
		t.Fatal("missing CIDR")
	}
}

func TestExpiredAndRevoked(t *testing.T) {
	issuer, _ := identity.Generate()
	spec := testSpec()
	spec.TTL = time.Millisecond
	bundle, err := Issue(issuer, spec)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	st := store.NewMemory()
	if err := Consume(st, trust.New(st), bundle.Manifest, bundle.Token); err == nil {
		t.Fatal("expired")
	}
	spec.TTL = time.Hour
	bundle, _ = Issue(issuer, spec)
	st = store.NewMemory()
	_ = Revoke(st, bundle.Manifest.RevocationID)
	if err := Consume(st, trust.New(st), bundle.Manifest, bundle.Token); err == nil {
		t.Fatal("revoked")
	}
}

func TestWrongTokenAndTamper(t *testing.T) {
	issuer, _ := identity.Generate()
	bundle, _ := Issue(issuer, testSpec())
	if err := VerifyToken(bundle.Manifest, []byte("nope")); err == nil {
		t.Fatal("wrong token")
	}
	bundle.Manifest.Flags.DesktopMode = desktop.ModeUnattended
	if _, err := Verify(bundle.Manifest); err == nil {
		t.Fatal("tamper")
	}
}

func TestAddressScope(t *testing.T) {
	issuer, _ := identity.Generate()
	bundle, _ := Issue(issuer, testSpec())
	if err := AddressAllowed(bundle.Manifest, "10.9.1.2:1"); err != nil {
		t.Fatal(err)
	}
	if err := AddressAllowed(bundle.Manifest, "8.8.8.8:1"); err == nil {
		t.Fatal("wan should be out of scope")
	}
}

func TestPolicyTextVisible(t *testing.T) {
	issuer, _ := identity.Generate()
	bundle, _ := Issue(issuer, testSpec())
	txt := PolicyText(bundle.Manifest)
	for _, n := range []string{"identity-signed", "Desktop mode", "one-time", "never contain reusable private keys"} {
		if !bytes.Contains([]byte(txt), []byte(n)) {
			t.Fatalf("policy missing %q in %s", n, txt)
		}
	}
}
