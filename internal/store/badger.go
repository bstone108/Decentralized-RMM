package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
)

type Badger struct {
	db   *badger.DB
	path string
}

type OpenOptions struct {
	Path           string
	SyncWrites     bool
	RecoverCorrupt bool
	// KeyPath is the at-rest key file. Empty uses EnvKeyFile, then
	// DefaultKeyPath (a sibling of the store directory, never inside it).
	KeyPath string
	// EncryptionKey, when set, is a 32-byte AES-256 key used for this open.
	// It is not written to the key file and is never logged. Leave it empty
	// in production so the key file is the source of truth.
	EncryptionKey []byte
	// failpoint aborts plaintext migration at a named stage ("after-copy",
	// "corrupt-copy", "after-source-renamed"). Tests in this package set it.
	failpoint string
}

func OpenBadger(path string) (*Badger, error) {
	return OpenBadgerOptions(OpenOptions{Path: path, SyncWrites: true, RecoverCorrupt: true})
}

func OpenBadgerOptions(opt OpenOptions) (*Badger, error) {
	if opt.Path == "" {
		return nil, fmt.Errorf("badger path is required")
	}
	if err := recoverMigrationLayout(opt.Path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opt.Path, 0o700); err != nil {
		return nil, err
	}
	kind, err := inspectStore(opt.Path)
	if err != nil {
		return nil, err
	}
	key, err := resolveKey(opt, kind)
	if err != nil {
		return nil, err
	}
	if kind == kindPlaintext {
		if err := migratePlaintext(opt.Path, key, opt.failpoint); err != nil {
			if opt.RecoverCorrupt && errors.Is(err, errPlaintextUnreadable) {
				return reopenAfterQuarantine(opt, key, err)
			}
			return nil, err
		}
	}
	if err := discardVerifiedPlaintext(opt.Path, key); err != nil {
		return nil, err
	}
	db, err := openEncryptedDB(opt.Path, key, opt.SyncWrites)
	if err != nil {
		if isKeyRejection(err) {
			return nil, fmt.Errorf("%w: %s was left unchanged", ErrAtRestKeyRejected, opt.Path)
		}
		if !opt.RecoverCorrupt {
			return nil, err
		}
		return reopenAfterQuarantine(opt, key, err)
	}
	st := &Badger{db: db, path: opt.Path}
	if err := st.ensureSchema(); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
}

func reopenAfterQuarantine(opt OpenOptions, key []byte, openErr error) (*Badger, error) {
	q, qerr := Quarantine(opt.Path)
	if qerr != nil {
		return nil, fmt.Errorf("badger open: %w (quarantine failed: %v)", openErr, qerr)
	}
	if err := os.MkdirAll(opt.Path, 0o700); err != nil {
		return nil, fmt.Errorf("badger open after quarantine to %s: %w", q, err)
	}
	db, err := openEncryptedDB(opt.Path, key, opt.SyncWrites)
	if err != nil {
		return nil, fmt.Errorf("badger reopen after quarantine to %s: %w", q, err)
	}
	st := &Badger{db: db, path: opt.Path}
	if err := st.ensureSchema(); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
}

func Quarantine(path string) (string, error) {
	dest := path + ".quarantine." + time.Now().UTC().Format("20060102T150405Z")
	if err := os.Rename(path, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func (s *Badger) ensureSchema() error {
	key := Key(PrefixMeta, "schema")
	raw, ok, err := s.Get(key)
	if err != nil {
		return err
	}
	meta := map[string]int{"version": SchemaVersion}
	if !ok {
		return PutJSON(s, key, meta)
	}
	var existing map[string]int
	if err := json.Unmarshal(raw, &existing); err != nil {
		return fmt.Errorf("schema record corrupt: %w", err)
	}
	if existing["version"] > SchemaVersion {
		return fmt.Errorf("store schema %d is newer than binary %d", existing["version"], SchemaVersion)
	}
	return nil
}

func (s *Badger) Get(key []byte) ([]byte, bool, error) {
	if err := AssertAllowedKey(key); err != nil {
		return nil, false, err
	}
	var out []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return err
		}
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			out = append([]byte(nil), v...)
			return nil
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, false, nil
	}
	return out, err == nil, err
}

func (s *Badger) Put(key, value []byte) error {
	if err := AssertAllowedKey(key); err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

func (s *Badger) CompareAndSwap(key, old, new []byte) error {
	if err := AssertAllowedKey(key); err != nil {
		return err
	}
	err := s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			if len(old) != 0 {
				return ErrCASConflict
			}
			return txn.Set(key, new)
		}
		if err != nil {
			return err
		}
		var cur []byte
		if err := item.Value(func(v []byte) error {
			cur = append([]byte(nil), v...)
			return nil
		}); err != nil {
			return err
		}
		if !bytes.Equal(cur, old) {
			return ErrCASConflict
		}
		return txn.Set(key, new)
	})
	return err
}

func (s *Badger) Delete(key []byte) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

func (s *Badger) PrefixScan(prefix []byte, fn func(key, value []byte) error) error {
	return s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		if prefix == nil {
			prefix = []byte{}
		}
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.KeyCopy(nil)
			if err := item.Value(func(v []byte) error {
				return fn(k, append([]byte(nil), v...))
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Badger) Export(w io.Writer) error {
	_, err := s.db.Backup(w, 0)
	return err
}

func (s *Badger) Import(r io.Reader) error {
	return s.db.Load(r, 16)
}

func (s *Badger) Close() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *Badger) Backend() string { return "badger" }
func (s *Badger) Path() string    { return s.path }

// DumpValues concatenates all values for secret-leak tests. Not a public API.
func DumpValues(s Store) ([]byte, error) {
	var buf bytes.Buffer
	err := s.PrefixScan(nil, func(key, value []byte) error {
		buf.Write(key)
		buf.WriteByte(0)
		buf.Write(value)
		buf.WriteByte(0)
		return nil
	})
	return buf.Bytes(), err
}

func DataDir(root string) string {
	return filepath.Join(root, "rmm.badger")
}
