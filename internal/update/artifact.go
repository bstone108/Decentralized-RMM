package update

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

const Schema = "rmm-artifact-v1"

type Component string

const (
	ComponentAgent   Component = "rmm-agent"
	ComponentConsole Component = "rmm-console"
	ComponentPack    Component = "rmm-pack"
)

type Artifact struct {
	Schema          string    `json:"schema"`
	Component       Component `json:"component"`
	Version         string    `json:"version"`
	GOOS            string    `json:"goos"`
	GOARCH          string    `json:"goarch"`
	SHA256          string    `json:"sha256"`
	Size            int       `json:"size"`
	ExpiresAt       time.Time `json:"expiresAt"`
	PublisherNodeID string    `json:"publisherNodeID"`
	PublisherKey    string    `json:"publisherPublicKey"`
	Source          string    `json:"source"` // github|mesh|local
	SourceURL       string    `json:"sourceURL,omitempty"`
	Signature       string    `json:"signature,omitempty"`
}

type Envelope struct {
	Artifact Artifact `json:"artifact"`
	Payload  []byte   `json:"payload"`
}

func Sign(publisher identity.Private, component Component, version, goos, goarch string, payload []byte, ttl time.Duration, source string) (Envelope, error) {
	sum := sha256.Sum256(payload)
	art := Artifact{
		Schema:          Schema,
		Component:       component,
		Version:         version,
		GOOS:            goos,
		GOARCH:          goarch,
		SHA256:          hex.EncodeToString(sum[:]),
		Size:            len(payload),
		ExpiresAt:       time.Now().UTC().Add(ttl),
		PublisherNodeID: publisher.Public.NodeID,
		PublisherKey:    publisher.Public.KeyBase64,
		Source:          source,
	}
	sig := publisher.Sign(canonical(art))
	art.Signature = base64.StdEncoding.EncodeToString(sig)
	return Envelope{Artifact: art, Payload: append([]byte(nil), payload...)}, nil
}

func Verify(env Envelope, expectedPublisher string, now time.Time, requireLocalPlatform bool) error {
	art := env.Artifact
	if art.Schema != Schema {
		return fmt.Errorf("unsupported artifact schema")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.After(art.ExpiresAt) {
		return fmt.Errorf("artifact expired")
	}
	if requireLocalPlatform && (art.GOOS != runtime.GOOS || art.GOARCH != runtime.GOARCH) {
		return fmt.Errorf("artifact os/arch %s/%s does not match %s/%s", art.GOOS, art.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	sum := sha256.Sum256(env.Payload)
	if hex.EncodeToString(sum[:]) != art.SHA256 {
		return fmt.Errorf("artifact hash mismatch")
	}
	if art.Size != len(env.Payload) {
		return fmt.Errorf("artifact size mismatch")
	}
	pub, err := identity.ParsePublic(art.PublisherKey)
	if err != nil {
		return err
	}
	if pub.NodeID != art.PublisherNodeID {
		return fmt.Errorf("publisher node id mismatch")
	}
	if expectedPublisher != "" && pub.NodeID != expectedPublisher {
		return fmt.Errorf("artifact publisher is not the trusted release issuer")
	}
	sig, err := base64.StdEncoding.DecodeString(art.Signature)
	if err != nil {
		return err
	}
	copyA := art
	copyA.Signature = ""
	return pub.Verify(canonical(copyA), sig)
}

func AllowVersion(current, candidate string, rollback bool) error {
	if current == "" || current == candidate {
		return nil
	}
	cmp := compareVersion(current, candidate)
	if rollback {
		if cmp < 0 {
			return fmt.Errorf("rollback target %s is not older than %s", candidate, current)
		}
		return nil
	}
	if cmp >= 0 {
		return fmt.Errorf("version policy refuses non-upgrade %s → %s", current, candidate)
	}
	return nil
}

type Cache struct {
	Store store.Store
}

func (c Cache) Put(env Envelope) error {
	if err := Verify(env, env.Artifact.PublisherNodeID, time.Time{}, false); err != nil {
		return err
	}
	key := artifactKey(env.Artifact)
	return store.PutJSON(c.Store, key, env)
}

func (c Cache) Get(component Component, version, goos, goarch string) (Envelope, bool, error) {
	var env Envelope
	ok, err := store.GetJSON(c.Store, store.Key(store.PrefixArtifact, string(component), version, goos, goarch), &env)
	return env, ok, err
}

func (c Cache) List() ([]Artifact, error) {
	var out []Artifact
	err := c.Store.PrefixScan([]byte(store.PrefixArtifact), func(key, value []byte) error {
		var env Envelope
		if err := json.Unmarshal(value, &env); err != nil {
			return err
		}
		env.Payload = nil
		out = append(out, env.Artifact)
		return nil
	})
	return out, err
}

func artifactKey(a Artifact) []byte {
	return store.Key(store.PrefixArtifact, string(a.Component), a.Version, a.GOOS, a.GOARCH)
}

type ApplyPlan struct {
	Staged   string
	Backup   string
	Current  string
	Artifact Artifact
}

func Stage(dir string, env Envelope, currentVersion string, rollback bool) (ApplyPlan, error) {
	if err := Verify(env, env.Artifact.PublisherNodeID, time.Time{}, true); err != nil {
		return ApplyPlan{}, err
	}
	if err := AllowVersion(currentVersion, env.Artifact.Version, rollback); err != nil {
		return ApplyPlan{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ApplyPlan{}, err
	}
	name := string(env.Artifact.Component)
	if env.Artifact.GOOS == "windows" {
		name += ".exe"
	}
	current := filepath.Join(dir, name)
	staged := current + ".new"
	backup := current + ".bak"
	if err := os.WriteFile(staged, env.Payload, 0o755); err != nil {
		return ApplyPlan{}, err
	}
	return ApplyPlan{Staged: staged, Backup: backup, Current: current, Artifact: env.Artifact}, nil
}

func Apply(plan ApplyPlan) error {
	if _, err := os.Stat(plan.Current); err == nil {
		_ = os.Remove(plan.Backup)
		if err := os.Rename(plan.Current, plan.Backup); err != nil {
			return err
		}
	}
	if err := os.Rename(plan.Staged, plan.Current); err != nil {
		if _, berr := os.Stat(plan.Backup); berr == nil {
			_ = os.Rename(plan.Backup, plan.Current)
		}
		return err
	}
	return nil
}

func Rollback(plan ApplyPlan) error {
	if _, err := os.Stat(plan.Backup); err != nil {
		return fmt.Errorf("no backup for rollback")
	}
	if _, err := os.Stat(plan.Current); err == nil {
		_ = os.Rename(plan.Current, plan.Current+".failed")
	}
	return os.Rename(plan.Backup, plan.Current)
}

func Receipt(st store.Store, art Artifact, status, summary string) error {
	rec := intent.Receipt{
		IntentID:  "update:" + string(art.Component) + ":" + art.Version,
		Status:    intent.Status(status),
		Kind:      "app.update",
		UpdatedAt: time.Now().UTC(),
		Summary:   summary,
	}
	if err := intent.SaveReceipt(st, rec); err != nil {
		return err
	}
	return store.PutJSON(st, store.Key(store.PrefixUpdate, string(art.Component), art.Version), map[string]string{
		"status": status, "summary": summary, "sha256": art.SHA256,
	})
}

func canonical(a Artifact) []byte {
	copyA := a
	copyA.Signature = ""
	raw, _ := json.Marshal(copyA)
	return raw
}

func compareVersion(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

// AcceptFromPeer copies a mesh-provided envelope only after independent
// verification against the trusted publisher. Peers cannot introduce untrusted
// updates even if they are otherwise paired.
func AcceptFromPeer(c Cache, env Envelope, trustedPublisher string) error {
	if env.Artifact.Source == "" {
		env.Artifact.Source = "mesh"
	}
	if err := Verify(env, trustedPublisher, time.Time{}, false); err != nil {
		return err
	}
	return c.Put(env)
}
