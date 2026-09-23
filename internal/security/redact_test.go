package security

import "testing"

func TestRedactAndContainsSecret(t *testing.T) {
	if RedactString("auth failed for password=hunter2") != "[redacted]" {
		t.Fatal("expected redaction")
	}
	if RedactString("intent inventory.collect ok") == "[redacted]" {
		t.Fatal("false positive")
	}
	secret := []byte("never-store-this-admin-password")
	if !ContainsSecret([]byte("wrap never-store-this-admin-password wrap"), secret) {
		t.Fatal("should detect")
	}
	if ContainsSecret([]byte("receipt elevationUsed=true"), secret) {
		t.Fatal("false positive")
	}
	if !LooksLikeSecretField("adminPassword") {
		t.Fatal("field")
	}
}
