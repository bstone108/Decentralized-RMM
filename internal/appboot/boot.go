package appboot

import (
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

func Open(data string, role node.Role) (store.Store, *node.Node, error) {
	st, err := store.OpenBadger(store.DataDir(data))
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
