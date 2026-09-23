package node

import (
	"encoding/json"
	"fmt"

	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/host"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func applyIntent(n *Node, in intent.Intent, proof *desktop.ElevationProof) (json.RawMessage, string, error) {
	switch in.Kind {
	case intent.KindInventoryCollect:
		snap := host.Collect()
		if err := store.PutJSON(n.Store, store.Key(store.PrefixInv, "local"), snap); err != nil {
			return nil, "inventory persist failed", err
		}
		raw, err := json.Marshal(snap)
		return raw, "inventory collected", err
	case intent.KindDesktopModeChange:
		var p struct {
			Mode desktop.Mode `json:"mode"`
		}
		if err := json.Unmarshal(in.Payload, &p); err != nil {
			return nil, "invalid payload", err
		}
		pol, err := desktop.ChangeMode(n.Store, p.Mode, proof, n.Verify, true)
		if err != nil {
			return nil, "desktop mode change failed", err
		}
		raw, err := json.Marshal(map[string]any{"mode": pol.Mode, "elevationUsed": proof != nil})
		return raw, "desktop mode updated", err
	case intent.KindCommandRun:
		return nil, "command.run disabled", fmt.Errorf("command.run is disabled until a signed authz policy exists")
	case intent.KindConfigApply, intent.KindAppInstall, intent.KindAppUpdate,
		intent.KindAppRemove, intent.KindAppVerify, intent.KindServiceControl,
		intent.KindDesktopSession:
		raw, _ := json.Marshal(map[string]string{"status": "stub"})
		return raw, "kind accepted; backend not implemented in this milestone", nil
	default:
		return nil, "unknown kind", fmt.Errorf("unknown intent kind %q", in.Kind)
	}
}
