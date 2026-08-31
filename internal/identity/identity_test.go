package identity

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateSignVerifyAndFingerprint(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidNodeID(id.Public.NodeID) {
		t.Fatalf("node id %q", id.Public.NodeID)
	}
	msg := []byte("rmm-hello-v1")
	sig := id.Sign(msg)
	if err := id.Public.Verify(msg, sig); err != nil {
		t.Fatal(err)
	}
	if err := id.Public.Verify([]byte("other"), sig); err == nil {
		t.Fatal("expected verify failure")
	}
	parsed, err := ParsePublic(id.Public.KeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.NodeID != id.Public.NodeID {
		t.Fatalf("fingerprint mismatch %s vs %s", parsed.NodeID, id.Public.NodeID)
	}
	round, err := ParseSeed(id.SeedBase64())
	if err != nil {
		t.Fatal(err)
	}
	if round.Public.NodeID != id.Public.NodeID {
		t.Fatal("seed round-trip changed node id")
	}
	if bytes.Contains([]byte(id.Public.NodeID), []byte(id.SeedBase64())) {
		t.Fatal("node id must not embed the private seed")
	}
	if !strings.HasPrefix(id.Public.NodeID, NodeIDPrefix) {
		t.Fatal("node id prefix")
	}
}
