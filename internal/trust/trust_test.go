package trust

import (
	"testing"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func TestPairAndRejectUnknown(t *testing.T) {
	st := store.NewMemory()
	book := New(st)
	a, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := book.Add(Offer(a, "agent")); err != nil {
		t.Fatal(err)
	}
	ok, err := book.Trusted(a.Public.NodeID)
	if err != nil || !ok {
		t.Fatalf("trusted=%v err=%v", ok, err)
	}
	b, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := book.Require(b.Public.NodeID); err == nil {
		t.Fatal("unknown peer must be untrusted")
	}
	bad := Offer(a, "agent")
	bad.NodeID = "rmm1:not-the-fingerprint"
	if err := book.Add(bad); err == nil {
		t.Fatal("mismatched fingerprint must fail")
	}
}
