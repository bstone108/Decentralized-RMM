package store

import (
	"bytes"
	"fmt"
	"io"
)

const (
	SchemaVersion = 1

	PrefixRMM     = "rmm/v1/"
	PrefixPrivate = "rmm/v1/private/"
	PrefixTrust   = "rmm/v1/trust/"
	PrefixIntent  = "rmm/v1/intent/"
	PrefixIdem    = "rmm/v1/intent-idem/"
	PrefixReceipt = "rmm/v1/receipt/"
	PrefixAudit   = "rmm/v1/audit/"
	PrefixInv     = "rmm/v1/inventory/"
	PrefixDesktop = "rmm/v1/desktop/"
	PrefixMeta    = "rmm/v1/meta/"
	PrefixInterop = "interop/mgmt/v1/"

	// ForbiddenPrefix is File-Sync-Engine's on-disk prefix. RMM must never
	// read or write it, and validation fails if it appears.
	ForbiddenPrefix = "fse/v1/"
)

var allowedPrefixes = []string{
	PrefixPrivate, PrefixTrust, PrefixIntent, PrefixIdem, PrefixReceipt,
	PrefixAudit, PrefixInv, PrefixDesktop, PrefixMeta, PrefixInterop,
}

type Store interface {
	Get(key []byte) ([]byte, bool, error)
	Put(key, value []byte) error
	Delete(key []byte) error
	PrefixScan(prefix []byte, fn func(key, value []byte) error) error
	Export(w io.Writer) error
	Import(r io.Reader) error
	Close() error
	Backend() string
	Path() string
}

func Key(parts ...string) []byte {
	var b bytes.Buffer
	for i, p := range parts {
		if i > 0 && !bytes.HasSuffix(b.Bytes(), []byte("/")) && p != "" && p[0] != '/' {
			b.WriteByte('/')
		}
		b.WriteString(p)
	}
	return b.Bytes()
}

func AssertAllowedKey(key []byte) error {
	if bytes.HasPrefix(key, []byte(ForbiddenPrefix)) || bytes.HasPrefix(key, []byte("fse/")) {
		return fmt.Errorf("refusing File-Sync-Engine key prefix %q", key)
	}
	for _, p := range allowedPrefixes {
		if bytes.HasPrefix(key, []byte(p)) {
			return nil
		}
	}
	if bytes.Equal(key, []byte(PrefixRMM+"meta/schema")) || bytes.HasPrefix(key, []byte(PrefixMeta)) {
		return nil
	}
	return fmt.Errorf("key %q is outside rmm/v1 and interop/mgmt/v1 namespaces", key)
}

func Validate(s Store) error {
	return s.PrefixScan(nil, func(key, value []byte) error {
		if err := AssertAllowedKey(key); err != nil {
			return err
		}
		if bytes.Contains(bytes.ToLower(key), []byte("password")) {
			return fmt.Errorf("key must not contain password material: %q", key)
		}
		if bytes.Contains(bytes.ToLower(value), []byte("\"password\"")) {
			return fmt.Errorf("value must not persist a password field under %q", key)
		}
		return nil
	})
}
