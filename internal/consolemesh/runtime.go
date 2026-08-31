package consolemesh

import (
	"fmt"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/localpeer"
	"github.com/bstone108/Decentralized-RMM/internal/node"
)

type Mode string

const (
	ModeViaLocalAgent Mode = "via_local_agent"
	ModeBuiltin       Mode = "builtin"
)

type Runtime struct {
	Node      *node.Node
	Mode      Mode
	MeshAddr  string
	LocalAddr string
}

func Start(n *node.Node, dataDir, listenAddr string) (*Runtime, error) {
	if n.Role != node.RoleConsole {
		return nil, fmt.Errorf("console runtime requires the console component")
	}
	adv, ok, err := localpeer.Read(dataDir)
	if err != nil {
		return nil, err
	}
	if ok {
		peer, perr := n.Trust.Require(adv.NodeID)
		if perr == nil && peer.PublicKey == adv.PublicKey && adv.Role == "agent" {
			if _, err := identity.ParsePublicWithBox(adv.PublicKey, adv.BoxPublicKey); err == nil {
				return &Runtime{Node: n, Mode: ModeViaLocalAgent, LocalAddr: adv.ListenAddr}, nil
			}
		}
	}
	bound, err := n.Listen(listenAddr)
	if err != nil {
		return nil, err
	}
	return &Runtime{Node: n, Mode: ModeBuiltin, MeshAddr: bound}, nil
}
