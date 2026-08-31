package localpeer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReadAgentOnly(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, Advertisement{NodeID: "rmm1:a", PublicKey: "k", ListenAddr: "127.0.0.1:1", Role: "console"}); err == nil {
		t.Fatal("console must not advertise as local agent")
	}
	if err := Write(dir, Advertisement{NodeID: "rmm1:a", PublicKey: "k", ListenAddr: "127.0.0.1:9", Role: "agent"}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(Path(dir))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm %s", st.Mode())
	}
	adv, ok, err := Read(dir)
	if err != nil || !ok || adv.ListenAddr != "127.0.0.1:9" {
		t.Fatalf("%+v %v %v", adv, ok, err)
	}
	if DataDirFromStorePath(filepath.Join(dir, "rmm.badger")) != dir {
		t.Fatal("data dir")
	}
}
