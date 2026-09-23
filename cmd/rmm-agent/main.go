package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bstone108/Decentralized-RMM/internal/appboot"
	"github.com/bstone108/Decentralized-RMM/internal/consoleui"
	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/node"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
	"github.com/bstone108/Decentralized-RMM/internal/update"
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
		st, n, err := appboot.Open(*data, node.RoleAgent)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		fmt.Printf("initialized agent %s in %s\n", n.ID.Public.NodeID, *data)
	case "identity":
		fs := flag.NewFlagSet("identity", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		_ = fs.Parse(os.Args[2:])
		st, n, err := appboot.Open(*data, node.RoleAgent)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(trust.Offer(n.ID, "agent"))
	case "pair":
		fs := flag.NewFlagSet("pair", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		peerKey := fs.String("peer-key", "", "peer Ed25519 public key (standard base64)")
		peerBox := fs.String("peer-box", "", "peer X25519 box public key (standard base64)")
		peerID := fs.String("peer-id", "", "peer node id (rmm1:...)")
		role := fs.String("peer-role", "console", "peer role")
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
		st, n, err := appboot.Open(*data, node.RoleAgent)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		if err := n.Pair(trust.Peer{NodeID: pub.NodeID, PublicKey: pub.KeyBase64, BoxPublicKey: pub.BoxKeyBase64, Role: *role}); err != nil {
			appboot.Fatal(err)
		}
		fmt.Printf("trusted %s\n", pub.NodeID)
	case "listen":
		fs := flag.NewFlagSet("listen", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		addr := fs.String("addr", "127.0.0.1:7946", "listen address")
		_ = fs.Parse(os.Args[2:])
		st, n, err := appboot.Open(*data, node.RoleAgent)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		man, applied, err := n.EnrollFromDir(*data)
		if err != nil {
			appboot.Fatal(err)
		}
		if man.EnrollmentID != "" {
			title, body := consoleui.EnrollmentPolicy(man)
			_ = consoleui.Native{PolicyFile: enroll.PolicyFile(*data)}.ShowPolicy(title, body)
			if applied {
				fmt.Printf("consumed enrollment grant %s (%s)\n", man.Grant(), man.Scope.AllowedUses.PolicyLine())
			}
		}
		bound, err := n.Listen(*addr)
		if err != nil {
			appboot.Fatal(err)
		}
		fmt.Printf("agent %s listening on %s\n", n.ID.Public.NodeID, bound)
		select {}
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		dir := fs.String("from", "", "directory with enrollment.manifest.json and enrollment.token")
		_ = fs.Parse(os.Args[2:])
		if *dir == "" {
			appboot.Fatal(fmt.Errorf("--from is required"))
		}
		st, n, err := appboot.Open(*data, node.RoleAgent)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		man, applied, err := n.EnrollFromDir(*dir)
		if err != nil {
			appboot.Fatal(err)
		}
		title, body := consoleui.EnrollmentPolicy(man)
		_ = consoleui.Native{PolicyFile: filepath.Join(*data, "POLICY.txt")}.ShowPolicy(title, body)
		fmt.Printf("enrollment %s applied=%v\n", man.EnrollmentID, applied)
	case "update-ingest":
		fs := flag.NewFlagSet("update-ingest", flag.ExitOnError)
		data := fs.String("data", appboot.DefaultDataDir(), "data directory")
		file := fs.String("file", "", "signed .rmm-artifact envelope")
		_ = fs.Parse(os.Args[2:])
		if *file == "" {
			appboot.Fatal(fmt.Errorf("--file is required"))
		}
		st, n, err := appboot.Open(*data, node.RoleAgent)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		raw, err := os.ReadFile(*file)
		if err != nil {
			appboot.Fatal(err)
		}
		pub, ok, err := enroll.LoadPublisher(st)
		if err != nil || !ok {
			appboot.Fatal(fmt.Errorf("trusted publisher required from enrollment: %v", err))
		}
		env, err := update.Ingest(n.UpdateCache(), raw, pub)
		if err != nil {
			appboot.Fatal(err)
		}
		fmt.Printf("cached %s %s %s/%s sha256=%s\n", env.Artifact.Component, env.Artifact.Version, env.Artifact.GOOS, env.Artifact.GOARCH, env.Artifact.SHA256)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `rmm-agent %s — platform agent (endpoint management)

The agent is separately deployable from rmm-console. It has no operator GUI.

Commands:
  version
  init --data DIR
  identity --data DIR
  pair --data DIR --peer-key B64 [--peer-box B64]
  enroll --data DIR --from PACKDIR
  listen --data DIR --addr 127.0.0.1:7946
  update-ingest --data DIR --file artifact.rmm-artifact
`, version)
}
