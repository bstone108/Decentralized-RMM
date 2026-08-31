package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/host"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
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
	case "listen":
		fs := flag.NewFlagSet("listen", flag.ExitOnError)
		data := fs.String("data", defaultDataDir(), "data directory")
		role := fs.String("role", "agent", "console|agent|dual")
		addr := fs.String("addr", "127.0.0.1:0", "listen address")
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
		bound, err := n.Listen(*addr)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("listening as %s %s on %s\n", n.Role, n.ID.Public.NodeID, bound)
		select {}
	case "intent":
		fs := flag.NewFlagSet("intent", flag.ExitOnError)
		data := fs.String("data", defaultDataDir(), "data directory")
		addr := fs.String("addr", "", "agent address host:port")
		target := fs.String("target", "", "target node id")
		kind := fs.String("kind", "inventory.collect", "intent kind")
		id := fs.String("id", "", "intent id (generated if empty)")
		_ = fs.Parse(os.Args[2:])
		if *addr == "" || *target == "" {
			fatal(fmt.Errorf("--addr and --target are required"))
		}
		st, err := store.OpenBadger(store.DataDir(*data))
		if err != nil {
			fatal(err)
		}
		defer st.Close()
		n, err := node.Open(st, node.RoleConsole, nil)
		if err != nil {
			fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		sess, err := n.Dial(ctx, *addr, *target)
		if err != nil {
			fatal(err)
		}
		defer sess.Close()
		intentID := *id
		if intentID == "" {
			intentID = fmt.Sprintf("cli-%d", time.Now().UnixNano())
		}
		queued, err := n.Queue(intent.New(intentID, intentID, n.ID.Public.NodeID, *target, intent.Kind(*kind), nil))
		if err != nil {
			fatal(err)
		}
		ack, err := n.Deliver(sess, queued.ID)
		if err != nil {
			fatal(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(ack)
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
  listen --data DIR --role agent --addr 127.0.0.1:7946
  intent --data DIR --addr HOST:PORT --target rmm1:... --kind inventory.collect
`, version)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
