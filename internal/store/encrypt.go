package store

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dgraph-io/badger/v4"
)

const (
	// EnvKeyFile overrides the default at-rest key path when OpenOptions.KeyPath
	// is empty. A --store-key-file flag, when set, wins over this variable.
	EnvKeyFile = "RMM_STORE_KEY_FILE"

	keyFileMagic          = "rmm-badger-key-v1"
	atRestKeyBytes        = 32
	indexCacheSize        = 64 << 20
	encNewSuffix          = ".enc-new"
	plaintextBackupSuffix = ".plaintext-backup"
	migrateStateSuffix    = ".enc-migrate"
	// registrySanity is Badger's KEYREGISTRY header. Stored in the clear when
	// the directory was opened without an encryption key (v4.2.0).
	registrySanity = "Hello Badger"
)

// ErrAtRestKeyMissing means an encrypted store has no key file and no
// in-process key was supplied. The directory is not modified.
var ErrAtRestKeyMissing = errors.New("badger at-rest encryption key is missing")

// ErrAtRestKeyRejected means the supplied key does not open the store.
// The directory is not modified and is not quarantined.
var ErrAtRestKeyRejected = errors.New("badger at-rest encryption key rejected")

var (
	errPlaintextUnreadable = errors.New("plaintext badger store is unreadable")
	errKeyFileExists       = errors.New("at-rest key file already exists")
)

type storeKind int

const (
	kindFresh storeKind = iota
	kindPlaintext
	kindEncrypted
	kindUnknown
)

// DefaultKeyPath is the at-rest key for a store directory. It is a sibling of
// the Badger directory (for example rmm.badger.key next to rmm.badger), never
// a file inside it, so a directory export or backup of the store does not
// include the key.
func DefaultKeyPath(storePath string) string {
	return storePath + ".key"
}

func resolveKeyPath(opt OpenOptions) (string, error) {
	p := opt.KeyPath
	if p == "" {
		p = os.Getenv(EnvKeyFile)
	}
	if p == "" {
		p = DefaultKeyPath(opt.Path)
	}
	absStore, err := filepath.Abs(opt.Path)
	if err != nil {
		return "", err
	}
	absKey, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if absKey == absStore || strings.HasPrefix(absKey, absStore+string(os.PathSeparator)) {
		return "", fmt.Errorf("at-rest key file must not live inside the Badger directory %s", opt.Path)
	}
	return p, nil
}

func resolveKey(opt OpenOptions, kind storeKind) ([]byte, error) {
	if len(opt.EncryptionKey) > 0 {
		if len(opt.EncryptionKey) != atRestKeyBytes {
			return nil, fmt.Errorf("at-rest encryption key must be %d bytes", atRestKeyBytes)
		}
		return append([]byte(nil), opt.EncryptionKey...), nil
	}
	path, err := resolveKeyPath(opt)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		return readKeyFile(path)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	switch kind {
	case kindFresh, kindPlaintext:
		key, err := generateKey()
		if err != nil {
			return nil, err
		}
		if err := writeKeyFile(path, key); err != nil {
			if errors.Is(err, errKeyFileExists) {
				return readKeyFile(path)
			}
			return nil, err
		}
		return key, nil
	case kindEncrypted:
		return nil, fmt.Errorf("%w: %s (store left unchanged; restore the key file from backup)", ErrAtRestKeyMissing, path)
	default:
		return nil, fmt.Errorf("unrecognized Badger directory %s left unchanged; not creating an at-rest key", opt.Path)
	}
}

func generateKey() ([]byte, error) {
	key := make([]byte, atRestKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate at-rest key: %w", err)
	}
	return key, nil
}

func writeKeyFile(path string, key []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".rmm-key-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	body := keyFileMagic + "\n" + base64.StdEncoding.EncodeToString(key) + "\n"
	if _, err := io.WriteString(tmp, body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, path); err != nil {
		if os.IsExist(err) {
			committed = true
			_ = os.Remove(tmpName)
			return errKeyFileExists
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			return err
		}
		// Some filesystems reject hard links. Rename is safe here only because
		// the destination was absent; the common path above is exclusive.
		if rerr := os.Rename(tmpName, path); rerr != nil {
			return err
		}
		committed = true
		if rerr := restrictKeyFile(path); rerr != nil {
			_ = os.Remove(path)
			return rerr
		}
		return nil
	}
	_ = os.Remove(tmpName)
	committed = true
	if err := restrictKeyFile(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func readKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(b))
	line, rest, ok := strings.Cut(text, "\n")
	if !ok || strings.TrimSpace(line) != keyFileMagic {
		return nil, fmt.Errorf("unrecognized at-rest key file %s", path)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil || len(raw) != atRestKeyBytes {
		return nil, fmt.Errorf("at-rest key file %s does not hold a %d-byte key", path, atRestKeyBytes)
	}
	return raw, nil
}

func inspectStore(path string) (storeKind, error) {
	f, err := os.Open(filepath.Join(path, badger.KeyRegistryFileName))
	if err != nil {
		if os.IsNotExist(err) {
			matches, gerr := filepath.Glob(filepath.Join(path, "MANIFEST*"))
			if gerr != nil {
				return kindUnknown, gerr
			}
			if len(matches) == 0 {
				return kindFresh, nil
			}
			return kindUnknown, nil
		}
		return kindUnknown, err
	}
	defer f.Close()
	buf := make([]byte, aes.BlockSize+len(registrySanity))
	if _, err := io.ReadFull(f, buf); err != nil {
		// An unreadable registry is not plaintext. Do not invent a key for it.
		return kindUnknown, nil
	}
	if bytes.Equal(buf[aes.BlockSize:], []byte(registrySanity)) {
		return kindPlaintext, nil
	}
	return kindEncrypted, nil
}

func encryptedOptions(path string, key []byte, sync bool) badger.Options {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil
	opts.SyncWrites = sync
	opts.EncryptionKey = key
	// Encrypted index blocks are not kept inside the table struct. A 64 MiB
	// cache holds decrypted indexes for an agent/console store without using
	// a server-sized cache. BlockCacheSize stays at Badger's default because
	// encryption panics when that cache is disabled.
	opts.IndexCacheSize = indexCacheSize
	return opts
}

func openEncryptedDB(path string, key []byte, sync bool) (*badger.DB, error) {
	if len(key) != atRestKeyBytes {
		return nil, fmt.Errorf("at-rest encryption key must be %d bytes", atRestKeyBytes)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	return badger.Open(encryptedOptions(path, key, sync))
}

func openPlainDB(path string) (*badger.DB, error) {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil
	opts.SyncWrites = false
	opts.ReadOnly = true
	return badger.Open(opts)
}

func isKeyRejection(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, badger.ErrEncryptionKeyMismatch) || errors.Is(err, badger.ErrInvalidEncryptionKey) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "Encryption key mismatch") || strings.Contains(msg, "Encryption key's length")
}

func streamBackup(src, dst *badger.DB) error {
	pr, pw := io.Pipe()
	backupErr := make(chan error, 1)
	go func() {
		_, err := src.Backup(pw, 0)
		_ = pw.CloseWithError(err)
		backupErr <- err
	}()
	loadErr := dst.Load(pr, 16)
	if loadErr != nil {
		_ = pr.CloseWithError(loadErr)
	}
	bErr := <-backupErr
	if loadErr != nil {
		return fmt.Errorf("load encrypted copy: %w", loadErr)
	}
	if bErr != nil {
		return fmt.Errorf("backup plaintext store: %w", bErr)
	}
	return nil
}

func copyEncrypted(srcPath, dstPath string, key []byte, failpoint string) (count int, sum [32]byte, err error) {
	src, err := openPlainDB(srcPath)
	if err != nil {
		return 0, sum, fmt.Errorf("open plaintext store: %v (%w)", err, errPlaintextUnreadable)
	}
	defer src.Close()

	dst, err := openEncryptedDB(dstPath, key, true)
	if err != nil {
		return 0, sum, fmt.Errorf("create encrypted store: %w", err)
	}
	defer dst.Close()

	if err := streamBackup(src, dst); err != nil {
		return 0, sum, err
	}
	if failpoint == "corrupt-copy" {
		if err := dst.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte(PrefixMeta+"migration-corrupt"), []byte("x"))
		}); err != nil {
			return 0, sum, err
		}
	}
	if err := dst.Sync(); err != nil {
		return 0, sum, err
	}
	c1, s1, err := checksumDB(src)
	if err != nil {
		return 0, sum, err
	}
	c2, s2, err := checksumDB(dst)
	if err != nil {
		return 0, sum, err
	}
	if c1 != c2 || s1 != s2 {
		return 0, sum, fmt.Errorf("migration verification failed: plaintext count %d checksum %s vs encrypted count %d checksum %s; original store left in place", c1, hex.EncodeToString(s1[:]), c2, hex.EncodeToString(s2[:]))
	}
	return c1, s1, nil
}

func checksumDB(db *badger.DB) (int, [32]byte, error) {
	h := sha256.New()
	var count int
	var sum [32]byte
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.IteratorOptions{
			PrefetchValues: true,
			PrefetchSize:   100,
			AllVersions:    true,
		})
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.KeyCopy(nil)
			if bytes.HasPrefix(k, []byte("!badger!")) {
				continue
			}
			var v []byte
			if err := item.Value(func(val []byte) error {
				v = append([]byte(nil), val...)
				return nil
			}); err != nil {
				return err
			}
			count++
			var hdr [8]byte
			binary.BigEndian.PutUint64(hdr[:], uint64(len(k)))
			if _, err := h.Write(hdr[:]); err != nil {
				return err
			}
			if _, err := h.Write(k); err != nil {
				return err
			}
			binary.BigEndian.PutUint64(hdr[:], item.Version())
			if _, err := h.Write(hdr[:]); err != nil {
				return err
			}
			binary.BigEndian.PutUint64(hdr[:], item.ExpiresAt())
			if _, err := h.Write(hdr[:]); err != nil {
				return err
			}
			flags := []byte{item.UserMeta(), 0}
			if item.IsDeletedOrExpired() {
				flags[1] = 1
			}
			if _, err := h.Write(flags); err != nil {
				return err
			}
			binary.BigEndian.PutUint64(hdr[:], uint64(len(v)))
			if _, err := h.Write(hdr[:]); err != nil {
				return err
			}
			if _, err := h.Write(v); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, sum, err
	}
	copy(sum[:], h.Sum(nil))
	return count, sum, nil
}

type migrateState struct {
	Stage  string `json:"stage"`
	Count  int    `json:"count"`
	SHA256 string `json:"sha256"`
}

func writeMigrateState(storePath string, count int, sum [32]byte) error {
	body, err := json.Marshal(migrateState{
		Stage:  "verified",
		Count:  count,
		SHA256: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return err
	}
	path := storePath + migrateStateSuffix
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	return os.Rename(tmp, path)
}

func migratePlaintext(path string, key []byte, failpoint string) error {
	dst := path + encNewSuffix
	if exists(dst) {
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
	}
	count, sum, err := copyEncrypted(path, dst, key, failpoint)
	if err != nil {
		_ = os.RemoveAll(dst)
		return err
	}
	if failpoint == "after-copy" {
		return fmt.Errorf("migration stopped after copy; original store at %s was left in place", path)
	}
	if err := writeMigrateState(path, count, sum); err != nil {
		return fmt.Errorf("record migration checksum: %w", err)
	}
	backup := path + plaintextBackupSuffix
	if exists(backup) {
		return fmt.Errorf("refusing to migrate %s because %s already exists", path, backup)
	}
	if err := os.Rename(path, backup); err != nil {
		return fmt.Errorf("move plaintext store aside: %w (original left at %s)", err, path)
	}
	if failpoint == "after-source-renamed" {
		return fmt.Errorf("migration stopped after moving the plaintext store to %s", backup)
	}
	if err := os.Rename(dst, path); err != nil {
		if rerr := os.Rename(backup, path); rerr != nil {
			return fmt.Errorf("swap into %s failed (%v) and restoring plaintext failed (%v); plaintext remains at %s", path, err, rerr, backup)
		}
		_ = os.RemoveAll(dst)
		return fmt.Errorf("swap into %s failed: %w; original restored", path, err)
	}
	if err := discardVerifiedPlaintext(path, key); err != nil {
		return err
	}
	_ = os.Remove(path + migrateStateSuffix)
	return nil
}

// discardVerifiedPlaintext deletes the plaintext sibling only after a second
// open of the encrypted store matches it. The copy is not kept: leaving it
// on disk would undo at-rest encryption. A mismatch keeps both directories.
func discardVerifiedPlaintext(path string, key []byte) error {
	backup := path + plaintextBackupSuffix
	if !exists(backup) {
		return nil
	}
	if !exists(path) {
		return fmt.Errorf("plaintext backup %s exists but %s is missing", backup, path)
	}
	kind, err := inspectStore(path)
	if err != nil {
		return err
	}
	if kind != kindEncrypted {
		return fmt.Errorf("refusing to remove %s while %s is not an encrypted store", backup, path)
	}
	c1, s1, err := checksumPath(path, key)
	if err != nil {
		return fmt.Errorf("reopen encrypted store before dropping plaintext: %w", err)
	}
	c2, s2, err := checksumPath(backup, nil)
	if err != nil {
		return fmt.Errorf("read plaintext backup %s: %w", backup, err)
	}
	if c1 != c2 || s1 != s2 {
		return fmt.Errorf("encrypted store does not match plaintext backup (count %d vs %d); both left on disk at %s and %s", c1, c2, path, backup)
	}
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("remove verified plaintext backup: %w", err)
	}
	_ = os.Remove(path + migrateStateSuffix)
	if exists(path + encNewSuffix) {
		_ = os.RemoveAll(path + encNewSuffix)
	}
	return nil
}

func checksumPath(path string, key []byte) (int, [32]byte, error) {
	var (
		db  *badger.DB
		err error
	)
	if key == nil {
		db, err = openPlainDB(path)
	} else {
		db, err = openEncryptedDB(path, key, true)
	}
	if err != nil {
		return 0, [32]byte{}, err
	}
	defer db.Close()
	return checksumDB(db)
}

func recoverMigrationLayout(path string) error {
	if isEmptyDir(path) && (exists(path+encNewSuffix) || exists(path+plaintextBackupSuffix)) {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	dst := path + encNewSuffix
	backup := path + plaintextBackupSuffix
	pathExists := exists(path)
	dstExists := exists(dst)
	backupExists := exists(backup)
	switch {
	case !pathExists && dstExists && backupExists:
		if err := os.Rename(dst, path); err != nil {
			return fmt.Errorf("resume encrypted swap for %s: %w", path, err)
		}
	case !pathExists && !dstExists && backupExists:
		if err := os.Rename(backup, path); err != nil {
			return fmt.Errorf("restore plaintext store to %s: %w", path, err)
		}
	case !pathExists && dstExists && !backupExists:
		return fmt.Errorf("refusing to promote unverified %s because the original store is missing", dst)
	case pathExists && dstExists && !backupExists:
		kind, err := inspectStore(path)
		if err != nil {
			return err
		}
		if kind == kindPlaintext || kind == kindFresh {
			if err := os.RemoveAll(dst); err != nil {
				return err
			}
		}
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isEmptyDir(path string) bool {
	ents, err := os.ReadDir(path)
	return err == nil && len(ents) == 0
}
