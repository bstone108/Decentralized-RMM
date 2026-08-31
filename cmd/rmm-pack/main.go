package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/appboot"
	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/node"
	"github.com/bstone108/Decentralized-RMM/internal/pack"
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
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		dir := fs.String("dir", ".", "installer tree")
		_ = fs.Parse(os.Args[2:])
		if err := pack.VerifyIndependent(*dir); err != nil {
			appboot.Fatal(err)
		}
		fmt.Println("artifact and enrollment manifest verified independently")
	case "build":
		fs := flag.NewFlagSet("build", flag.ExitOnError)
		out := fs.String("out", "dist/installers", "output directory")
		goos := fs.String("os", "", "target os (linux|darwin|windows)")
		goarch := fs.String("arch", "", "target arch")
		agentPath := fs.String("agent", "", "rmm-agent binary to embed")
		consolePath := fs.String("console", "", "optional separately-deployable rmm-console binary")
		issuerData := fs.String("issuer-data", "", "console data directory (issuer identity; private key never packed)")
		org := fs.String("org", "", "organization id")
		cidrs := fs.String("cidr", "", "comma-separated allowed CIDRs (required; 0.0.0.0/0 forbidden)")
		bootstrap := fs.String("bootstrap", "", "comma-separated nodeID=host:port bootstrap peers")
		desktopMode := fs.String("desktop", string(desktop.ModeAuthorizationRequired), "unattended|authorization-required")
		selfUpdate := fs.Bool("self-update", true, "allow secure self-update when policy permits")
		maxUses := fs.Int("max-uses", 1, "one-time/scoped enrollment uses")
		ttl := fs.Duration("ttl", 24*time.Hour, "enrollment expiry")
		rev := fs.String("revocation-id", "", "revocation identifier")
		dht := fs.Bool("allow-dht", false, "allow DHT candidate discovery (still not trust)")
		relay := fs.Bool("allow-relay", false, "allow relay bootstrap peers")
		_ = fs.Parse(os.Args[2:])
		if *agentPath == "" || *issuerData == "" || *org == "" || *cidrs == "" || *bootstrap == "" {
			appboot.Fatal(fmt.Errorf("--agent, --issuer-data, --org, --cidr, and --bootstrap are required"))
		}
		agentBin, err := os.ReadFile(*agentPath)
		if err != nil {
			appboot.Fatal(err)
		}
		var consoleBin []byte
		if *consolePath != "" {
			consoleBin, err = os.ReadFile(*consolePath)
			if err != nil {
				appboot.Fatal(err)
			}
		}
		st, n, err := appboot.Open(*issuerData, node.RoleConsole)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		spec := enroll.Spec{
			OrgID:        *org,
			MaxUses:      *maxUses,
			TTL:          *ttl,
			RevocationID: *rev,
			AllowDHT:     *dht,
			AllowRelay:   *relay,
			DesktopMode:  desktop.Mode(*desktopMode),
			SelfUpdate:   *selfUpdate,
		}
		for _, c := range strings.Split(*cidrs, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				spec.AllowedCIDRs = append(spec.AllowedCIDRs, c)
			}
		}
		for _, b := range strings.Split(*bootstrap, ",") {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			nodeID, addr, ok := strings.Cut(b, "=")
			if !ok {
				appboot.Fatal(fmt.Errorf("bootstrap must be nodeID=host:port"))
			}
			spec.BootstrapPeers = append(spec.BootstrapPeers, enroll.BootstrapPeer{
				NodeID: nodeID, Address: addr, Kind: "configured",
			})
		}
		res, err := pack.Build(*out, pack.Request{
			GOOS:          *goos,
			GOARCH:        *goarch,
			AgentBinary:   agentBin,
			ConsoleBinary: consoleBin,
			Publisher:     n.ID,
			Spec:          spec,
		})
		if err != nil {
			appboot.Fatal(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	case "sign-artifact":
		fs := flag.NewFlagSet("sign-artifact", flag.ExitOnError)
		issuerData := fs.String("issuer-data", "", "console data directory")
		bin := fs.String("bin", "", "component binary")
		component := fs.String("component", "rmm-agent", "rmm-agent|rmm-console|rmm-pack")
		ver := fs.String("version", "", "semver")
		goos := fs.String("os", runtime.GOOS, "target os")
		goarch := fs.String("arch", runtime.GOARCH, "target arch")
		out := fs.String("out", "", "output .rmm-artifact")
		ttl := fs.Duration("ttl", 720*time.Hour, "artifact expiry")
		_ = fs.Parse(os.Args[2:])
		if *issuerData == "" || *bin == "" || *ver == "" || *out == "" {
			appboot.Fatal(fmt.Errorf("--issuer-data, --bin, --version, --out required"))
		}
		payload, err := os.ReadFile(*bin)
		if err != nil {
			appboot.Fatal(err)
		}
		st, n, err := appboot.Open(*issuerData, node.RoleConsole)
		if err != nil {
			appboot.Fatal(err)
		}
		defer st.Close()
		env, err := update.Sign(n.ID, update.Component(*component), *ver, *goos, *goarch, payload, *ttl, "github")
		if err != nil {
			appboot.Fatal(err)
		}
		if err := update.WriteEnvelope(*out, env); err != nil {
			appboot.Fatal(err)
		}
		fmt.Printf("signed %s sha256=%s publisher=%s\n", *out, env.Artifact.SHA256, env.Artifact.PublisherNodeID)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `rmm-pack %s — identity-provisioned installer builder

Produces platform-native installer trees with an identity-signed enrollment
manifest (not merely code signing). Installers never embed reusable private
keys, passwords, or unrestricted network access.

Commands:
  version
  build --issuer-data DIR --agent BIN --org ID --cidr CIDR --bootstrap nodeID=addr
        [--os linux] [--arch amd64] [--desktop unattended] [--console BIN]
  verify --dir TREE
  sign-artifact --issuer-data DIR --bin BIN --version V --out FILE.rmm-artifact
`, version)
}
