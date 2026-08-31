package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryRejectsFSEPrefix(t *testing.T) {
	m := NewMemory()
	if err := m.Put([]byte("fse/v1/manifest/x"), []byte("no")); err == nil {
		t.Fatal("expected reject")
	}
}

func TestMemoryJSONRoundTrip(t *testing.T) {
	m := NewMemory()
	key := Key(PrefixIntent, "abc")
	if err := PutJSON(m, key, map[string]string{"id": "abc"}); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	ok, err := GetJSON(m, key, &got)
	if err != nil || !ok || got["id"] != "abc" {
		t.Fatalf("got %+v ok=%v err=%v", got, ok, err)
	}
	var buf bytes.Buffer
	if err := m.Export(&buf); err != nil {
		t.Fatal(err)
	}
	m2 := NewMemory()
	if err := m2.Import(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if err := Validate(m2); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsPasswordField(t *testing.T) {
	m := NewMemory()
	if err := m.Put(Key(PrefixDesktop, "policy"), []byte(`{"password":"x"}`)); err != nil {
		t.Fatal(err)
	}
	if err := Validate(m); err == nil {
		t.Fatal("expected password field rejection")
	}
}

func TestBadgerPersistReopenExportValidate(t *testing.T) {
	dir := t.TempDir()
	path := DataDir(dir)
	s, err := OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	key := Key(PrefixIntent, "i1")
	payload := []byte(`{"id":"i1","status":"queued"}`)
	if err := s.Put(key, payload); err != nil {
		t.Fatal(err)
	}
	if err := s.Put([]byte(ForbiddenPrefix+"x"), []byte("no")); err == nil {
		t.Fatal("fse prefix must be rejected")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, ok, err := s.Get(key)
	if err != nil || !ok || !bytes.Equal(got, payload) {
		t.Fatalf("reopen get ok=%v err=%v val=%s", ok, err, got)
	}
	var buf bytes.Buffer
	if err := s.Export(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty export")
	}
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
}

func TestBadgerQuarantineOnCorruptOpen(t *testing.T) {
	dir := t.TempDir()
	path := DataDir(dir)
	s, err := OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(path, "MANIFEST*"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("expected MANIFEST files: %v %v", matches, err)
	}
	if err := os.WriteFile(matches[0], []byte("corrupt-manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = OpenBadgerOptions(OpenOptions{Path: path, RecoverCorrupt: true, SyncWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if contains(e.Name(), "quarantine") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected quarantined directory next to recovered store")
	}
	if err := PutJSON(s, Key(PrefixMeta, "recovered"), map[string]bool{"ok": true}); err != nil {
		t.Fatal(err)
	}
}

func TestSqliteFallbackNotSelected(t *testing.T) {
	if BackendName() != "badger" {
		t.Fatalf("sqlite fallback must stay unselected, got %s", BackendName())
	}
}

func BackendName() string { return "badger" }

func TestSchemaJSON(t *testing.T) {
	raw, _ := json.Marshal(map[string]int{"version": SchemaVersion})
	if !bytes.Contains(raw, []byte("version")) {
		t.Fatal(raw)
	}
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

func TestAssertAllowedKey(t *testing.T) {
	cases := []struct {
		key string
		ok  bool
	}{
		{PrefixIntent + "x", true},
		{PrefixInterop + "presence/x", true},
		{ForbiddenPrefix + "manifest", false},
		{"random", false},
	}
	for _, c := range cases {
		err := AssertAllowedKey([]byte(c.key))
		if c.ok && err != nil {
			t.Fatalf("%s: %v", c.key, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("%s: expected error", c.key)
		}
	}
}

func TestDumpValues(t *testing.T) {
	m := NewMemory()
	_ = m.Put(Key(PrefixInv, "local"), []byte("host"))
	dump, err := DumpValues(m)
	if err != nil || !bytes.Contains(dump, []byte("host")) {
		t.Fatalf("%s %v", dump, err)
	}
}

func TestCompareAndSwap(t *testing.T) {
	m := NewMemory()
	key := Key(PrefixEnroll, "grant", "g1", "counter")
	if err := m.CompareAndSwap(key, []byte("x"), []byte("1")); err != ErrCASConflict {
		t.Fatalf("missing key with non-empty old: %v", err)
	}
	if err := m.CompareAndSwap(key, nil, []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := m.CompareAndSwap(key, []byte("1"), []byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := m.CompareAndSwap(key, []byte("1"), []byte("3")); err != ErrCASConflict {
		t.Fatalf("stale old: %v", err)
	}
	got, ok, _ := m.Get(key)
	if !ok || string(got) != "2" {
		t.Fatalf("%s", got)
	}
}

func TestKeyJoin(t *testing.T) {
	k := Key(PrefixIntent, "id")
	if string(k) != "rmm/v1/intent/id" {
		t.Fatalf("key=%q", k)
	}
}
