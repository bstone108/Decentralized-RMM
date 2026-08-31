package spike

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func TestBadgerCrossPlatformSpike(t *testing.T) {
	if os.Getenv("CGO_ENABLED") == "1" {
		t.Log("warning: CGO_ENABLED=1; the stack decision requires a CGO_ENABLED=0 run as well")
	}
	dir := t.TempDir()
	path := store.DataDir(dir)
	start := time.Now()
	s, err := store.OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	const n = 1000
	for i := 0; i < n; i++ {
		key := store.Key(store.PrefixIntent, fmt.Sprintf("spike-%04d", i))
		val := []byte(fmt.Sprintf(`{"id":"spike-%04d","status":"queued","kind":"inventory.collect"}`, i))
		if err := s.Put(key, val); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.OpenBadger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, ok, err := s.Get(store.Key(store.PrefixIntent, "spike-0000"))
	if err != nil || !ok || !bytes.Contains(got, []byte("queued")) {
		t.Fatalf("reopen %v %v %s", ok, err, got)
	}
	got, ok, err = s.Get(store.Key(store.PrefixIntent, "spike-0999"))
	if err != nil || !ok {
		t.Fatalf("last record missing")
	}
	var buf bytes.Buffer
	if err := s.Export(&buf); err != nil || buf.Len() == 0 {
		t.Fatalf("export: %v len=%d", err, buf.Len())
	}
	if err := store.Validate(s); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	t.Logf("host=%s/%s go=%s badger_open_1000put_reopen=%s export_bytes=%d sqlite_fallback=no",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), elapsed, buf.Len())
	if elapsed > 30*time.Second {
		t.Fatalf("spike too slow: %s", elapsed)
	}
}

func TestSqliteFallbackRemainsUnselected(t *testing.T) {
	if _, err := store.OpenSQLite("unused.sqlite"); err == nil {
		t.Fatal("sqlite must stay unselected")
	}
}
