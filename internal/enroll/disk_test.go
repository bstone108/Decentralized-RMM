package enroll

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

func TestApplyIfPresentOnceAndDropToken(t *testing.T) {
	issuer, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Issue(issuer, testSpec())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	man, err := json.MarshalIndent(bundle.Manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ManifestFile(dir), man, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(TokenFile(dir), []byte(TokenEncode(bundle.Token)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	book := trust.New(st)
	got, applied, err := ApplyIfPresent(st, book, dir)
	if err != nil || !applied || got.EnrollmentID != bundle.Manifest.EnrollmentID {
		t.Fatalf("%+v %v %v", got, applied, err)
	}
	if _, err := os.Stat(TokenFile(dir)); !os.IsNotExist(err) {
		t.Fatal("raw token must be removed after consume")
	}
	got, applied, err = ApplyIfPresent(st, book, dir)
	if err != nil || applied {
		t.Fatalf("restart must not re-consume: applied=%v err=%v", applied, err)
	}
	if got.EnrollmentID != bundle.Manifest.EnrollmentID {
		t.Fatal(got.EnrollmentID)
	}
}
