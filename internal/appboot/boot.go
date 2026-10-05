package appboot

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bstone108/Decentralized-RMM/internal/node"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func DefaultDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".rmm")
}

// KeyFileFlag is the operator override for the Badger at-rest key.
// An empty value keeps the default (sibling of the store directory, or
// RMM_STORE_KEY_FILE when that environment variable is set).
func KeyFileFlag(fs *flag.FlagSet) *string {
	return fs.String("store-key-file", "", "Badger at-rest key file (default: <data>/rmm.badger.key; env RMM_STORE_KEY_FILE)")
}

func Open(data string, role node.Role) (store.Store, *node.Node, error) {
	return OpenConfig(data, role, "")
}

func OpenConfig(data string, role node.Role, keyFile string) (store.Store, *node.Node, error) {
	st, err := store.OpenBadgerOptions(store.OpenOptions{
		Path:           store.DataDir(data),
		SyncWrites:     true,
		RecoverCorrupt: true,
		KeyPath:        keyFile,
	})
	if err != nil {
		return nil, nil, err
	}
	n, err := node.Open(st, role, nil)
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	n.SetPresenceDir(data)
	return st, n, nil
}

func Fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
