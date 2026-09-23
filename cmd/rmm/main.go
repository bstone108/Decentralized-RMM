package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bstone108/Decentralized-RMM/internal/host"
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
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `rmm %s — inventory helper (not a dual-role binary)

Console, agent, and packager are separately deployable:

  rmm-console  operator console / authenticated mesh peer (no agent function)
  rmm-agent    platform agent (endpoint management)
  rmm-pack     identity-provisioned installer builder

Commands:
  version
  host-info
`, version)
}
