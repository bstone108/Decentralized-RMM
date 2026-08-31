package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/store"
)

type Policy struct {
	Enabled          bool
	TrustedPublisher string
	CurrentVersion   string
	ApplyLocal       bool
	AllowRollback    bool
	Component        Component
	Adapter          Adapter
}

type Result struct {
	Cached   []Artifact
	Applied  *ApplyPlan
	Restart  RestartPlan
	Receipts int
}

// Ingest fetches a signed envelope (GitHub or mesh/LAN URL), verifies it
// independently, and caches it. Foreign OS/arch artifacts are cached and not
// applied.
func Ingest(c Cache, raw []byte, trustedPublisher string) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Envelope{}, err
	}
	if err := AcceptFromPeer(c, env, trustedPublisher); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

func DiscoverAndCache(ctx context.Context, src Source, c Cache, trustedPublisher string) ([]Artifact, error) {
	if trustedPublisher == "" {
		return nil, fmt.Errorf("trusted release publisher is required")
	}
	assets, err := src.List(ctx)
	if err != nil {
		return nil, err
	}
	var cached []Artifact
	for _, a := range assets {
		raw, err := src.Fetch(ctx, a.URL)
		if err != nil {
			return cached, err
		}
		env, err := Ingest(c, raw, trustedPublisher)
		if err != nil {
			return cached, err
		}
		cached = append(cached, env.Artifact)
	}
	return cached, nil
}

func ApplyLocal(st store.Store, dir string, env Envelope, pol Policy) (ApplyPlan, RestartPlan, error) {
	if !pol.Enabled {
		return ApplyPlan{}, RestartPlan{}, fmt.Errorf("self-update disabled by enrollment/admin policy")
	}
	if err := Verify(env, pol.TrustedPublisher, time.Time{}, true); err != nil {
		return ApplyPlan{}, RestartPlan{}, err
	}
	plan, err := Stage(dir, env, pol.CurrentVersion, pol.AllowRollback)
	if err != nil {
		return ApplyPlan{}, RestartPlan{}, err
	}
	if err := Apply(plan); err != nil {
		_ = Receipt(st, env.Artifact, "failed", err.Error())
		return plan, RestartPlan{}, err
	}
	if err := Receipt(st, env.Artifact, "succeeded", "staged and applied after independent verification"); err != nil {
		return plan, RestartPlan{}, err
	}
	ad := pol.Adapter
	if ad == nil {
		ad = NativeAdapter()
	}
	return plan, ad.Restart(env.Artifact.Component), nil
}

func Recover(plan ApplyPlan, st store.Store) error {
	if err := Rollback(plan); err != nil {
		return err
	}
	return Receipt(st, plan.Artifact, "failed", "rolled back after apply failure")
}

// WriteEnvelope is the publisher-side release asset format.
func WriteEnvelope(path string, env Envelope) error {
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}
