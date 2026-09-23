package interop

import (
	"testing"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
)

func TestWrapUnwrapAndForbiddenTypes(t *testing.T) {
	a, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Wrap(a, b.Public, TypePresence, []byte(`{"role":"agent","caps":["intent.v1"]}`))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Unwrap(b, a.Public, env)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != `{"role":"agent","caps":["intent.v1"]}` {
		t.Fatalf("%s", pt)
	}
	if _, err := Wrap(a, b.Public, "folder_block", []byte("x")); err == nil {
		t.Fatal("forbidden type")
	}
	if _, err := Wrap(a, b.Public, TypeIntentRef, []byte(`{"password":"nope"}`)); err == nil {
		t.Fatal("password")
	}
	if _, err := Wrap(a, b.Public, TypeAckRef, []byte(`{"key":"fse/v1/manifest"}`)); err == nil {
		t.Fatal("fse prefix")
	}
}
