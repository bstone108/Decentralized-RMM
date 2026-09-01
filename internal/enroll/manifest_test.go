package enroll

import (
	"bytes"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

func testSpec() Spec {
	return Spec{
		OrgID:       "acme",
		TargetOS:    []string{runtime.GOOS},
		TargetArch:  []string{runtime.GOARCH},
		AllowedUses: AllowedUses{Mode: UseExactlyOne, Count: 1},
		TTL:         time.Hour,
		BootstrapPeers: []BootstrapPeer{{
			NodeID: "rmm1:console", Address: "10.1.2.3:7946", Kind: "configured",
		}},
		AllowedCIDRs: []string{"10.0.0.0/8"},
		DesktopMode:  desktop.ModeAuthorizationRequired,
		SelfUpdate:   true,
	}
}

func TestIssueVerifyConsumeExactlyOne(t *testing.T) {
	issuer, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Issue(issuer, testSpec())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Manifest.GrantID == "" || bundle.Manifest.GrantID != bundle.Manifest.RevocationID {
		t.Fatalf("unique revocable grant id required: %+v", bundle.Manifest)
	}
	st := store.NewMemory()
	book := trust.New(st)
	rec, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.UseSeq != 1 || rec.Mode != UseExactlyOne {
		t.Fatalf("%+v", rec)
	}
	if _, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, "agent-b"); err == nil {
		t.Fatal("exactly-one grant must refuse a second enrollee")
	}
	again, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, "agent-a")
	if err != nil || again.UseSeq != 1 {
		t.Fatalf("same enrollee restart must not take another use: %+v %v", again, err)
	}
	dump, _ := store.DumpValues(st)
	if bytes.Contains(dump, bundle.Token) {
		t.Fatal("raw grant credential must not be stored")
	}
	if bytes.Contains(dump, []byte(issuer.SeedBase64())) {
		t.Fatal("issuer private key must not be stored from enrollment")
	}
	got, err := ListReceipts(st, bundle.Manifest.Grant())
	if err != nil || len(got) != 1 {
		t.Fatalf("receipts %v %v", got, err)
	}
}

func TestFiniteAndUnlimitedUses(t *testing.T) {
	issuer, _ := identity.Generate()
	spec := testSpec()
	spec.AllowedUses = AllowedUses{Mode: UseFinite, Count: 3}
	bundle, err := Issue(issuer, spec)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	book := trust.New(st)
	for i, id := range []string{"a", "b", "c"} {
		rec, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, id)
		if err != nil || rec.UseSeq != i+1 {
			t.Fatalf("use %d: %+v %v", i+1, rec, err)
		}
	}
	if _, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, "d"); err == nil {
		t.Fatal("finite:3 must exhaust")
	}
	receipts, _ := ListReceipts(st, bundle.Manifest.Grant())
	if len(receipts) != 3 {
		t.Fatalf("want 3 receipts got %d", len(receipts))
	}

	spec.AllowedUses = AllowedUses{Mode: UseUnlimited}
	unlim, err := Issue(issuer, spec)
	if err != nil {
		t.Fatal(err)
	}
	st = store.NewMemory()
	book = trust.New(st)
	for i := 0; i < 8; i++ {
		if _, err := ConsumeFor(st, book, unlim.Manifest, unlim.Token, fmtNode(i)); err != nil {
			t.Fatal(i, err)
		}
	}
	receipts, _ = ListReceipts(st, unlim.Manifest.Grant())
	if len(receipts) != 8 {
		t.Fatalf("unlimited must keep a receipt per use, got %d", len(receipts))
	}
}

func fmtNode(i int) string { return "n-" + strconv.Itoa(i) }

func TestAtomicFiniteConsume(t *testing.T) {
	issuer, _ := identity.Generate()
	spec := testSpec()
	spec.AllowedUses = AllowedUses{Mode: UseFinite, Count: 5}
	bundle, _ := Issue(issuer, spec)
	st := store.NewMemory()
	book := trust.New(st)
	var ok atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "node-" + strconv.Itoa(i)
			if _, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, id); err == nil {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if ok.Load() != 5 {
		t.Fatalf("atomic finite: want 5 successes got %d", ok.Load())
	}
	n, err := useCount(st, bundle.Manifest.Grant())
	if err != nil || n != 5 {
		t.Fatalf("counter %d %v", n, err)
	}
}

func TestRevokePreventsFutureKeepsHistory(t *testing.T) {
	issuer, _ := identity.Generate()
	spec := testSpec()
	spec.AllowedUses = AllowedUses{Mode: UseFinite, Count: 4}
	bundle, _ := Issue(issuer, spec)
	st := store.NewMemory()
	book := trust.New(st)
	_ = book.Add(trust.Offer(issuer, "console"))
	if _, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, "a"); err != nil {
		t.Fatal(err)
	}
	notice, err := SignRevocation(issuer, bundle.Manifest.Grant(), ReasonRetired)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyRevocation(st, book, notice); err != nil {
		t.Fatal(err)
	}
	if _, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, "b"); err == nil {
		t.Fatal("revoked grant must not enroll")
	}
	receipts, _ := ListReceipts(st, bundle.Manifest.Grant())
	if len(receipts) != 1 {
		t.Fatalf("historic receipts must be retained, got %d", len(receipts))
	}
	events, err := intent.ListAudit(st)
	if err != nil || len(events) < 2 {
		t.Fatalf("audit retained: %d %v", len(events), err)
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
	_ = Revoke(st, bundle.Manifest.Grant())
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
	for _, n := range []string{"identity-signed", "Desktop mode", "exactly-one", "Grant ID", "never contain reusable private keys"} {
		if !bytes.Contains([]byte(txt), []byte(n)) {
			t.Fatalf("policy missing %q in %s", n, txt)
		}
	}
}

func TestParseUses(t *testing.T) {
	one, err := ParseUses("exactly-one")
	if err != nil || one.Mode != UseExactlyOne {
		t.Fatal(one, err)
	}
	alias, err := ParseUses("one")
	if err != nil || alias.Mode != UseExactlyOne {
		t.Fatal(alias, err)
	}
	fin, err := ParseUses("finite:12")
	if err != nil || fin.Count != 12 {
		t.Fatal(fin, err)
	}
	un, err := ParseUses("unlimited")
	if err != nil || un.Mode != UseUnlimited {
		t.Fatal(un, err)
	}
	if _, err := ParseUses("finite:0"); err == nil {
		t.Fatal("zero finite")
	}
}

func TestUniqueGrantIDsPerInstaller(t *testing.T) {
	issuer, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a, err := Issue(issuer, testSpec())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Issue(issuer, testSpec())
	if err != nil {
		t.Fatal(err)
	}
	if a.Manifest.GrantID == "" || a.Manifest.GrantID == b.Manifest.GrantID {
		t.Fatalf("each installer grant must have a unique revocable id: %s %s", a.Manifest.GrantID, b.Manifest.GrantID)
	}
	if a.Manifest.GrantID != a.Manifest.RevocationID {
		t.Fatal("grant id is the revocation handle")
	}
}

func TestUnlimitedStillEnforcesScopeExpiryAndRevoke(t *testing.T) {
	issuer, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	spec := testSpec()
	spec.AllowedUses = AllowedUses{Mode: UseUnlimited}
	spec.TTL = time.Millisecond
	expired, err := Issue(issuer, spec)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	st := store.NewMemory()
	if _, err := ConsumeFor(st, trust.New(st), expired.Manifest, expired.Token, "late"); err == nil {
		t.Fatal("unlimited grant must still expire")
	}

	spec.TTL = time.Hour
	live, err := Issue(issuer, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddressAllowed(live.Manifest, "8.8.8.8:1"); err == nil {
		t.Fatal("unlimited grant must still enforce CIDR scope")
	}
	st = store.NewMemory()
	book := trust.New(st)
	_ = book.Add(trust.Offer(issuer, "console"))
	if _, err := ConsumeFor(st, book, live.Manifest, live.Token, "a"); err != nil {
		t.Fatal(err)
	}
	notice, err := SignRevocation(issuer, live.Manifest.Grant(), ReasonRetired)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyRevocation(st, book, notice); err != nil {
		t.Fatal(err)
	}
	if _, err := ConsumeFor(st, book, live.Manifest, live.Token, "b"); err == nil {
		t.Fatal("retired unlimited grant must not enroll")
	}
	receipts, err := ListReceipts(st, live.Manifest.Grant())
	if err != nil || len(receipts) != 1 {
		t.Fatalf("historic receipts must be retained after retire: %d %v", len(receipts), err)
	}
}
