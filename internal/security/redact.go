package security

import (
	"bytes"
	"regexp"
	"strings"
)

var (
	passwordKeys = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|private[_-]?key|admin[_-]?pass)`)
)

// RedactString replaces likely secrets. Elevation passwords must never survive
// this function in logs or receipts.
func RedactString(s string) string {
	if s == "" {
		return s
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") {
		return "[redacted]"
	}
	return s
}

// ContainsSecret reports whether haystack includes the secret bytes. Used to
// assert stores/exports/logs never persist elevation proofs.
func ContainsSecret(haystack []byte, secret []byte) bool {
	if len(secret) == 0 {
		return false
	}
	return bytes.Contains(haystack, secret)
}

func LooksLikeSecretField(name string) bool {
	return passwordKeys.MatchString(name)
}
