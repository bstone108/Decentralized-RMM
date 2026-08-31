package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/appboot"
	"github.com/bstone108/Decentralized-RMM/internal/consolemesh"
	"github.com/bstone108/Decentralized-RMM/internal/consoleui"
	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/node"
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
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		_ = fs.Parse(os.Args[2:])
		st, n, err := appboot.Open(*data, node.RoleConsole)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		fmt.Printf("initialized console %s in %s\n", n.ID.Public.NodeID, *data)
	case "identity":
		fs := flag.NewFlagSet("identity", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		_ = fs.Parse(os.Args[2:])
		st, n, err := appboot.Open(*data, node.RoleConsole)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(trust.Offer(n.ID, "console"))
	case "pair":
		fs := flag.NewFlagSet("pair", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		peerKey := fs.String("peer-key", "", "peer Ed25519 public key (standard base64)")
		peerBox := fs.String("peer-box", "", "peer X25519 box public key (standard base64)")
		peerID := fs.String("peer-id", "", "peer node id (rmm1:...)")
		role := fs.String("peer-role", "agent", "peer role")
		_ = fs.Parse(os.Args[2:])
		if *peerKey == "" {
			appboot.Fatal(fmt.Errorf("--peer-key is required"))
		}
		pub, err := identity.ParsePublicWithBox(*peerKey, *peerBox)
		if err != nil {
			appboot.Fatal(err)
		}
		if *peerID != "" && *peerID != pub.NodeID {
			appboot.Fatal(fmt.Errorf("peer-id does not match key fingerprint %s", pub.NodeID))
		}
		st, n, err := appboot.Open(*data, node.RoleConsole)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		if err := n.Pair(trust.Peer{NodeID: pub.NodeID, PublicKey: pub.KeyBase64, BoxPublicKey: pub.BoxKeyBase64, Role: *role}); err != nil {
			appboot.Fatal(err)
		}
		fmt.Printf("trusted %s\n", pub.NodeID)
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		addr := fs.String("addr", "127.0.0.1:7947", "builtin mesh listen if no local agent")
		agentData := fs.String("agent-data", "", "same-host agent data dir (default: --data)")
		_ = fs.Parse(os.Args[2:])
		st, n, err := appboot.Open(*data, node.RoleConsole)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		lookup := *agentData
		if lookup == "" {
			lookup = *data
		}
		rt, err := consolemesh.Start(n, lookup, *addr)
		if err != nil {
			appboot.Fatal(err)
		}
		fmt.Printf("console %s mesh mode=%s local=%s builtin=%s\n", n.ID.Public.NodeID, rt.Mode, rt.LocalAddr, rt.MeshAddr)
		fmt.Println("console has no endpoint-management agent function")
		select {}
	case "policy":
		fs := flag.NewFlagSet("policy", flag.ExitOnError)
		file := fs.String("manifest", "", "enrollment.manifest.json")
		out := fs.String("out", "POLICY.txt", "policy visibility file")
		_ = fs.Parse(os.Args[2:])
		if *file == "" {
			appboot.Fatal(fmt.Errorf("--manifest is required"))
		}
		bundle, err := enroll.LoadBundle(filepath.Dir(*file))
		if err != nil {
			raw, rerr := os.ReadFile(*file)
			if rerr != nil {
				appboot.Fatal(err)
			}
			var m enroll.Manifest
			if jerr := json.Unmarshal(raw, &m); jerr != nil {
				appboot.Fatal(jerr)
			}
			bundle.Manifest = m
		}
		title, body := consoleui.EnrollmentPolicy(bundle.Manifest)
		if err := (consoleui.Native{PolicyFile: *out}).ShowPolicy(title, body); err != nil {
			appboot.Fatal(err)
		}
		fmt.Print(body)
	case "intent":
		fs := flag.NewFlagSet("intent", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		addr := fs.String("addr", "", "agent address host:port")
		target := fs.String("target", "", "target node id")
		kind := fs.String("kind", "inventory.collect", "intent kind")
		id := fs.String("id", "", "intent id (generated if empty)")
		_ = fs.Parse(os.Args[2:])
		if *addr == "" || *target == "" {
			appboot.Fatal(fmt.Errorf("--addr and --target are required"))
		}
		st, n, err := appboot.Open(*data, node.RoleConsole)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		sess, err := n.Dial(ctx, *addr, *target)
		if err != nil {
			appboot.Fatal(err)
		}
		defer sess.Close()
		intentID := *id
		if intentID == "" {
			intentID = fmt.Sprintf("cli-%d", time.Now().UnixNano())
		}
		queued, err := n.Queue(intent.New(intentID, intentID, n.ID.Public.NodeID, *target, intent.Kind(*kind), nil))
		if err != nil {
			appboot.Fatal(err)
		}
		ack, err := n.Deliver(sess, queued.ID)
		if err != nil {
			appboot.Fatal(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(ack)
	case "revoke":
		fs := flag.NewFlagSet("revoke", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		grant := fs.String("grant", "", "unique grant ID")
		reason := fs.String("reason", enroll.ReasonRevoked, "revoked|retired")
		addr := fs.String("addr", "", "optional trusted peer to publish the signed revocation")
		target := fs.String("target", "", "peer node id when --addr is set")
		_ = fs.Parse(os.Args[2:])
		if *grant == "" {
			appboot.Fatal(fmt.Errorf("--grant is required"))
		}
		st, n, err := appboot.Open(*data, node.RoleConsole)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		notice, err := n.RevokeGrant(*grant, *reason)
		if err != nil {
			appboot.Fatal(err)
		}
		if *addr != "" {
			if *target == "" {
				appboot.Fatal(fmt.Errorf("--target is required with --addr"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			sess, err := n.Dial(ctx, *addr, *target)
			if err != nil {
				appboot.Fatal(err)
			}
			defer sess.Close()
			if err := n.PublishRevocation(sess, notice); err != nil {
				appboot.Fatal(err)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(notice)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `rmm-console %s — operator console (mesh peer, not an agent)

Separately deployable from rmm-agent. Native on Windows/Linux/macOS.
If a trusted platform agent is on this computer, GUI/CLI prefers that local
authenticated connection and reuses the agent's mesh presence; otherwise the
console starts its own built-in authenticated mesh.

This process has no endpoint-management agent function, no TUI, and is not a
mandatory web console.

Commands:
  version
  init --data DIR
  identity --data DIR
  pair --data DIR --peer-key B64
  run --data DIR [--agent-data DIR] [--addr 127.0.0.1:7947]
  policy --manifest enrollment.manifest.json
  intent --data DIR --addr HOST:PORT --target rmm1:... --kind inventory.collect
  revoke --data DIR --grant GRANTID [--reason revoked|retired] [--addr HOST:PORT --target rmm1:...]
`, version)
}
