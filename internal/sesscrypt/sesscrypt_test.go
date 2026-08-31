package sesscrypt

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTripAndTamper(t *testing.T) {
	a, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	sa, err := SharedSecret(a, b.PubB64)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := SharedSecret(b, a.PubB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("shared secret mismatch")
	}
	na := []byte("nonce-aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	nb := []byte("nonce-bbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	ka, err := Derive(sa, na, nb, "rmm1:aaa", "rmm1:bbb")
	if err != nil {
		t.Fatal(err)
	}
	kb, err := Derive(sb, na, nb, "rmm1:bbb", "rmm1:aaa")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Seal(ka.Send, ka.SendPrefix, 1, []byte(`{"type":"intent"}`))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(kb.Recv, kb.RecvPrefix, 1, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != `{"type":"intent"}` {
		t.Fatalf("pt=%s", pt)
	}
	ct[0] ^= 0xff
	if _, err := Open(kb.Recv, kb.RecvPrefix, 1, ct); err == nil {
		t.Fatal("tamper must fail")
	}
	if err := ValidateLevel(4, false); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLevel(0, false); err == nil {
		t.Fatal("debug level must be refused")
	}
}
