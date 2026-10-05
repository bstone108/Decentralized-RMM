package store

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dgraph-io/badger/v4"
)

func TestFreshStoreEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := DataDir(dir)
	s, err := OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	key := Key(PrefixIntent, "fresh")
	payload := []byte(`{"id":"fresh","status":"queued"}`)
	if err := s.Put(key, payload); err != nil {
		t.Fatal(err)
	}
	if err := s.Put([]byte(ForbiddenPrefix+"x"), []byte("no")); err == nil {
		t.Fatal("fse prefix must be rejected")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	kind, err := inspectStore(path)
	if err != nil || kind != kindEncrypted {
		t.Fatalf("kind=%v err=%v", kind, err)
	}
	if registryIsPlaintext(t, path) {
		t.Fatal("KEYREGISTRY sanity text is still plaintext")
	}
	keyPath := DefaultKeyPath(path)
	rel, err := filepath.Rel(path, keyPath)
	if err != nil || !strings.HasPrefix(rel, "..") {
		t.Fatalf("key file %s is inside the store", keyPath)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode %o, want 0600", fi.Mode().Perm())
		}
	}
	rawKey := mustReadKey(t, keyPath)

	s, err = OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, ok, err := s.Get(key)
	if err != nil || !ok || !bytes.Equal(got, payload) {
		t.Fatalf("reopen ok=%v err=%v val=%s", ok, err, got)
	}
	if err := s.Put(Key(PrefixDesktop, "policy"), []byte(`{"password":"x"}`)); err != nil {
		t.Fatal(err)
	}
	if err := Validate(s); err == nil {
		t.Fatal("expected password field rejection")
	}
	var buf bytes.Buffer
	if err := s.Export(&buf); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), rawKey) || bytes.Contains(buf.Bytes(), []byte(base64.StdEncoding.EncodeToString(rawKey))) {
		t.Fatal("export contains the at-rest key")
	}
	if buf.Len() == 0 {
		t.Fatal("empty export")
	}
}

func TestReopenRejectsWrongAndMissingKey(t *testing.T) {
	dir := t.TempDir()
	path := DataDir(dir)
	s, err := OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	key := Key(PrefixIntent, "kept")
	payload := []byte("keep-me")
	if err := s.Put(key, payload); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	keyPath := DefaultKeyPath(path)
	saved, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	raw := mustReadKey(t, keyPath)

	wrong := bytes.Repeat([]byte{0x5a}, atRestKeyBytes)
	_, err = OpenBadgerOptions(OpenOptions{
		Path:           path,
		SyncWrites:     true,
		RecoverCorrupt: true,
		EncryptionKey:  wrong,
	})
	if !errors.Is(err, ErrAtRestKeyRejected) {
		t.Fatalf("wrong key: %v", err)
	}
	if strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(raw)) || bytes.Contains([]byte(err.Error()), raw) {
		t.Fatal("error includes key material")
	}
	if quarantined(t, dir) {
		t.Fatal("wrong key quarantined the store")
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	_, err = OpenBadgerOptions(OpenOptions{Path: path, SyncWrites: true, RecoverCorrupt: true})
	if !errors.Is(err, ErrAtRestKeyMissing) {
		t.Fatalf("missing key: %v", err)
	}
	if quarantined(t, dir) {
		t.Fatal("missing key quarantined the store")
	}
	if err := os.WriteFile(keyPath, saved, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err = OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, ok, err := s.Get(key)
	if err != nil || !ok || !bytes.Equal(got, payload) {
		t.Fatalf("data after rejected opens ok=%v err=%v val=%s", ok, err, got)
	}
}

func TestKeyFileEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := DataDir(dir)
	custom := filepath.Join(dir, "secrets", "badger.key")
	t.Setenv(EnvKeyFile, custom)
	s, err := OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Key(PrefixMeta, "env"), []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(DefaultKeyPath(path)); !os.IsNotExist(err) {
		t.Fatalf("default key path exists: %v", err)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Fatal(err)
	}
	s, err = OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, ok, err := s.Get(Key(PrefixMeta, "env"))
	if err != nil || !ok || string(got) != "1" {
		t.Fatalf("ok=%v err=%v val=%s", ok, err, got)
	}
}

func TestKeyPathOverrideAndInsideStoreRejected(t *testing.T) {
	dir := t.TempDir()
	path := DataDir(dir)
	custom := filepath.Join(dir, "operator.key")
	s, err := OpenBadgerOptions(OpenOptions{Path: path, SyncWrites: true, RecoverCorrupt: true, KeyPath: custom})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Key(PrefixAudit, "a"), []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(DefaultKeyPath(path)); !os.IsNotExist(err) {
		t.Fatalf("default key created despite override: %v", err)
	}
	s, err = OpenBadgerOptions(OpenOptions{Path: path, SyncWrites: true, RecoverCorrupt: true, KeyPath: custom})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, err = OpenBadgerOptions(OpenOptions{
		Path:           filepath.Join(dir, "other.badger"),
		SyncWrites:     true,
		RecoverCorrupt: true,
		KeyPath:        filepath.Join(dir, "other.badger", "nested.key"),
	})
	if err == nil || !strings.Contains(err.Error(), "must not live inside") {
		t.Fatalf("inside key path: %v", err)
	}
}

func TestMigratePlaintextStore(t *testing.T) {
	dir := t.TempDir()
	path := DataDir(dir)
	want := seedPlaintext(t, path, 30)

	s, err := OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assertRecords(t, s, want)
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	kind, err := inspectStore(path)
	if err != nil || kind != kindEncrypted {
		t.Fatalf("kind=%v err=%v", kind, err)
	}
	if exists(path + plaintextBackupSuffix) {
		t.Fatal("plaintext backup still present after verified migration")
	}
	if exists(path + encNewSuffix) {
		t.Fatal("encrypted sibling still present")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assertRecords(t, s, want)
}

func TestMigrationFailureLeavesOriginalIntact(t *testing.T) {
	t.Run("after-copy", func(t *testing.T) {
		dir := t.TempDir()
		path := DataDir(dir)
		want := seedPlaintext(t, path, 12)
		_, err := OpenBadgerOptions(OpenOptions{Path: path, SyncWrites: true, RecoverCorrupt: true, failpoint: "after-copy"})
		if err == nil {
			t.Fatal("expected migration failure")
		}
		if quarantined(t, dir) {
			t.Fatal("failed migration quarantined the original")
		}
		assertPlaintextIntact(t, path, want)

		s, err := OpenBadger(path)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		assertRecords(t, s, want)
		if exists(path + plaintextBackupSuffix) {
			t.Fatal("plaintext backup remains after a later successful migration")
		}
	})

	t.Run("checksum-mismatch", func(t *testing.T) {
		dir := t.TempDir()
		path := DataDir(dir)
		want := seedPlaintext(t, path, 8)
		_, err := OpenBadgerOptions(OpenOptions{Path: path, SyncWrites: true, RecoverCorrupt: true, failpoint: "corrupt-copy"})
		if err == nil || !strings.Contains(err.Error(), "verification failed") {
			t.Fatalf("expected verification failure, got %v", err)
		}
		if exists(path + encNewSuffix) {
			t.Fatal("failed encrypted copy was kept")
		}
		if quarantined(t, dir) {
			t.Fatal("verification failure quarantined the original")
		}
		assertPlaintextIntact(t, path, want)
	})

	t.Run("crash-during-swap", func(t *testing.T) {
		dir := t.TempDir()
		path := DataDir(dir)
		want := seedPlaintext(t, path, 10)
		_, err := OpenBadgerOptions(OpenOptions{Path: path, SyncWrites: true, RecoverCorrupt: true, failpoint: "after-source-renamed"})
		if err == nil {
			t.Fatal("expected swap failure")
		}
		backup := path + plaintextBackupSuffix
		if !exists(backup) || !exists(path+encNewSuffix) {
			t.Fatalf("backup=%v enc-new=%v path=%v", exists(backup), exists(path+encNewSuffix), exists(path))
		}
		assertPlaintextIntact(t, backup, want)

		s, err := OpenBadger(path)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		assertRecords(t, s, want)
		if exists(backup) {
			t.Fatal("plaintext backup remains after recovery")
		}
	})
}

func seedPlaintext(t *testing.T, path string, n int) map[string]string {
	t.Helper()
	db := openLegacyPlaintext(t, path)
	defer db.Close()
	want := make(map[string]string, n)
	for i := 0; i < n; i++ {
		k := string(Key(PrefixIntent, strings.Repeat("k", 3)+string(rune('a'+i%26))+itoa(i)))
		v := strings.Repeat("v", i+1) + "\x00bin"
		if err := db.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte(k), []byte(v))
		}); err != nil {
			t.Fatal(err)
		}
		want[k] = v
	}
	return want
}

func openLegacyPlaintext(t *testing.T, path string) *badger.DB {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	opts := badger.DefaultOptions(path)
	opts.Logger = nil
	opts.SyncWrites = true
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func assertRecords(t *testing.T, s Store, want map[string]string) {
	t.Helper()
	got := map[string]string{}
	if err := s.PrefixScan(nil, func(key, value []byte) error {
		if bytes.Equal(key, Key(PrefixMeta, "schema")) {
			return nil
		}
		got[string(key)] = string(value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("count %d want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("key %s got %q want %q", k, got[k], v)
		}
	}
}

func assertPlaintextIntact(t *testing.T, path string, want map[string]string) {
	t.Helper()
	kind, err := inspectStore(path)
	if err != nil || kind != kindPlaintext {
		t.Fatalf("original kind=%v err=%v", kind, err)
	}
	db := openLegacyPlaintext(t, path)
	defer db.Close()
	got := map[string]string{}
	err = db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.KeyCopy(nil)
			if bytes.HasPrefix(k, []byte("!badger!")) {
				continue
			}
			if err := item.Value(func(v []byte) error {
				got[string(k)] = string(v)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("plaintext count %d want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("plaintext key %s got %q want %q", k, got[k], v)
		}
	}
}

func registryIsPlaintext(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.Open(filepath.Join(path, badger.KeyRegistryFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, aes.BlockSize+len(registrySanity))
	if _, err := io.ReadFull(f, buf); err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(buf[aes.BlockSize:], []byte(registrySanity))
}

func mustReadKey(t *testing.T, path string) []byte {
	t.Helper()
	k, err := readKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func quarantined(t *testing.T, dir string) bool {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), "quarantine") {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
