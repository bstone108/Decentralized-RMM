package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bstone108/Decentralized-RMM/internal/host"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/node"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

var version = "foundation-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "host-info":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(host.Collect())
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		data := fs.String("data", defaultDataDir(), "data directory")
		role := fs.String("role", "agent", "console|agent|dual")
		_ = fs.Parse(os.Args[2:])
		st, err := store.OpenBadger(store.DataDir(*data))
		if err != nil {
			fatal(err)
		}
		defer st.Close()
		n, err := node.Open(st, node.Role(*role), nil)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("initialized %s node %s in %s\n", n.Role, n.ID.Public.NodeID, st.Path())
	case "identity":
		fs := flag.NewFlagSet("identity", flag.ExitOnError)
		data := fs.String("data", defaultDataDir(), "data directory")
		_ = fs.Parse(os.Args[2:])
		st, err := store.OpenBadger(store.DataDir(*data))
		if err != nil {
			fatal(err)
		}
		defer st.Close()
		n, err := node.Open(st, node.RoleDual, nil)
		if err != nil {
			fatal(err)
		}
		offer := trust.Offer(n.ID, string(n.Role))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(offer)
	case "pair":
		fs := flag.NewFlagSet("pair", flag.ExitOnError)
		data := fs.String("data", defaultDataDir(), "data directory")
		peerKey := fs.String("peer-key", "", "peer Ed25519 public key (standard base64)")
		peerBox := fs.String("peer-box", "", "peer X25519 box public key (standard base64)")
		peerID := fs.String("peer-id", "", "peer node id (rmm1:...)")
		role := fs.String("peer-role", "agent", "peer role")
		_ = fs.Parse(os.Args[2:])
		if *peerKey == "" {
			fatal(fmt.Errorf("--peer-key is required"))
		}
		pub, err := identity.ParsePublicWithBox(*peerKey, *peerBox)
		if err != nil {
			fatal(err)
		}
		if *peerID != "" && *peerID != pub.NodeID {
			fatal(fmt.Errorf("peer-id does not match key fingerprint %s", pub.NodeID))
		}
		st, err := store.OpenBadger(store.DataDir(*data))
		if err != nil {
			fatal(err)
		}
		defer st.Close()
		n, err := node.Open(st, node.RoleDual, nil)
		if err != nil {
			fatal(err)
		}
		if err := n.Pair(trust.Peer{NodeID: pub.NodeID, PublicKey: pub.KeyBase64, BoxPublicKey: pub.BoxKeyBase64, Role: *role}); err != nil {
			fatal(err)
		}
		fmt.Printf("trusted %s\n", pub.NodeID)
	default:
		usage()
		os.Exit(2)
	}
}

func defaultDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".rmm")
}

func usage() {
	fmt.Fprintf(os.Stderr, `rmm %s — native decentralized remote management

Commands:
  version
  host-info
  init --data DIR --role console|agent|dual
  identity --data DIR
  pair --data DIR --peer-key B64 [--peer-box B64] [--peer-id rmm1:...]
`, version)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
