package desktop

import (
	"testing"

	"github.com/bstone108/Decentralized-RMM/internal/security"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func TestDefaultIsAuthorizationRequired(t *testing.T) {
	if DefaultPolicy().Mode != ModeAuthorizationRequired {
		t.Fatal(DefaultPolicy().Mode)
	}
}

func TestAuthorizeSession(t *testing.T) {
	p := DefaultPolicy()
	ok, _ := AuthorizeSession(p, SessionRequest{ViewerNodeID: "rmm1:x", HasLocalUser: true, LocalConsent: true})
	if !ok {
		t.Fatal("expected allow with consent")
	}
	ok, reason := AuthorizeSession(p, SessionRequest{ViewerNodeID: "rmm1:x", HasLocalUser: false})
	if ok || reason == "" {
		t.Fatal("headless auth-required must deny")
	}
	p.Mode = ModeUnattended
	ok, _ = AuthorizeSession(p, SessionRequest{ViewerNodeID: "rmm1:x", HasLocalUser: false})
	if !ok {
		t.Fatal("unattended should allow trusted viewer")
	}
}

func TestRemoteUnattendedNeedsProofAndDoesNotPersistPassword(t *testing.T) {
	st := store.NewMemory()
	secret := []byte("correct-horse-admin")
	v := PasswordVerifier{ExpectedUser: "root", ExpectedPass: secret}
	_, err := ChangeMode(st, ModeUnattended, nil, v, true)
	if err == nil {
		t.Fatal("missing proof")
	}
	proof := NewRemoteProof("root", secret)
	got, err := ChangeMode(st, ModeUnattended, proof, v, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != ModeUnattended {
		t.Fatal(got.Mode)
	}
	if len(proof.Password) != 0 {
		t.Fatal("proof must be zeroed")
	}
	dump, err := store.DumpValues(st)
	if err != nil {
		t.Fatal(err)
	}
	if security.ContainsSecret(dump, secret) {
		t.Fatal("password leaked into store")
	}
	if err := store.Validate(st); err != nil {
		t.Fatal(err)
	}
}

func TestNoUsablePasswordRequiresLocalAccess(t *testing.T) {
	st := store.NewMemory()
	v := PasswordVerifier{NoUsablePass: true}
	if _, err := ChangeMode(st, ModeUnattended, NewRemoteProof("root", []byte("x")), v, true); err == nil {
		t.Fatal("expected refuse")
	}
	got, err := ChangeMode(st, ModeUnattended, NewLocalAccess(), v, false)
	if err != nil || got.Mode != ModeUnattended {
		t.Fatalf("local access should work: %+v %v", got, err)
	}
}

func TestRemoteCannotClaimLocalAccess(t *testing.T) {
	st := store.NewMemory()
	p := NewLocalAccess()
	p.remoteCaller = true
	if _, err := ChangeMode(st, ModeUnattended, p, PasswordVerifier{}, true); err == nil {
		t.Fatal("expected reject")
	}
}
