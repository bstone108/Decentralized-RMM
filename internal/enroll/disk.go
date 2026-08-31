package enroll

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

func ManifestFile(dir string) string { return filepath.Join(dir, "enrollment.manifest.json") }
func TokenFile(dir string) string    { return filepath.Join(dir, "enrollment.token") }
func PolicyFile(dir string) string   { return filepath.Join(dir, "POLICY.txt") }

func LoadManifest(dir string) (Manifest, error) {
	manRaw, err := os.ReadFile(ManifestFile(dir))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(manRaw, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func LoadBundle(dir string) (Bundle, error) {
	m, err := LoadManifest(dir)
	if err != nil {
		return Bundle{}, err
	}
	tokRaw, err := os.ReadFile(TokenFile(dir))
	if err != nil {
		return Bundle{}, fmt.Errorf("enrollment token missing for independent verification: %w", err)
	}
	token, err := TokenDecode(strings.TrimSpace(string(tokRaw)))
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Manifest: m, Token: token}, nil
}

// ApplyIfPresent consumes a grant from dir when files exist. A node that
// already applied this grant is a no-op (restart must not take another use).
// Missing files are not an error (manual pairing remains valid). The raw
// grant credential is removed from the endpoint data directory after a
// successful consume; the hashed credential remains in the signed manifest.
func ApplyIfPresent(st store.Store, book *trust.Book, dir, enrolleeNodeID string) (Manifest, bool, error) {
	if dir == "" {
		return Manifest{}, false, nil
	}
	if _, err := os.Stat(ManifestFile(dir)); os.IsNotExist(err) {
		return Manifest{}, false, nil
	}
	m, err := LoadManifest(dir)
	if err != nil {
		return Manifest{}, false, err
	}
	if rec, ok, err := LocallyEnrolled(st, m.Grant(), enrolleeNodeID); err != nil {
		return Manifest{}, false, err
	} else if ok && rec.GrantID != "" {
		return m, false, nil
	}
	bundle, err := LoadBundle(dir)
	if err != nil {
		return Manifest{}, false, err
	}
	if _, err := ConsumeFor(st, book, bundle.Manifest, bundle.Token, enrolleeNodeID); err != nil {
		return Manifest{}, false, err
	}
	_ = os.Remove(TokenFile(dir))
	return bundle.Manifest, true, nil
}

func LoadPublisher(st store.Store) (string, bool, error) {
	var found string
	err := st.PrefixScan([]byte(store.Key(store.PrefixEnroll, "manifest")), func(key, value []byte) error {
		var m Manifest
		if err := json.Unmarshal(value, &m); err != nil {
			return err
		}
		if m.IntendedIdentity.PublisherNodeID != "" {
			found = m.IntendedIdentity.PublisherNodeID
		}
		return nil
	})
	return found, found != "", err
}

func SelfUpdateAllowed(st store.Store) (bool, error) {
	allowed := false
	err := st.PrefixScan([]byte(store.Key(store.PrefixEnroll, "manifest")), func(key, value []byte) error {
		var m Manifest
		if err := json.Unmarshal(value, &m); err != nil {
			return err
		}
		if m.Flags.SelfUpdate {
			allowed = true
		}
		return nil
	})
	return allowed, err
}
