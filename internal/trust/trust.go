package trust

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

type Peer struct {
	NodeID       string    `json:"nodeID"`
	PublicKey    string    `json:"publicKey"`
	BoxPublicKey string    `json:"boxPublicKey,omitempty"`
	Role         string    `json:"role,omitempty"`
	PairedAt     time.Time `json:"pairedAt"`
}

type Book struct {
	st store.Store
}

func New(st store.Store) *Book { return &Book{st: st} }

func (b *Book) Add(p Peer) error {
	if p.NodeID == "" || p.PublicKey == "" {
		return fmt.Errorf("peer node id and public key are required")
	}
	pub, err := identity.ParsePublicWithBox(p.PublicKey, p.BoxPublicKey)
	if err != nil {
		return err
	}
	if pub.NodeID != p.NodeID {
		return fmt.Errorf("peer node id does not match public key fingerprint")
	}
	if p.PairedAt.IsZero() {
		p.PairedAt = time.Now().UTC()
	}
	return store.PutJSON(b.st, store.Key(store.PrefixTrust, "peer", p.NodeID), p)
}

func (b *Book) Get(nodeID string) (Peer, bool, error) {
	var p Peer
	ok, err := store.GetJSON(b.st, store.Key(store.PrefixTrust, "peer", nodeID), &p)
	return p, ok, err
}

func (b *Book) Trusted(nodeID string) (bool, error) {
	_, ok, err := b.Get(nodeID)
	return ok, err
}

func (b *Book) Require(nodeID string) (Peer, error) {
	p, ok, err := b.Get(nodeID)
	if err != nil {
		return Peer{}, err
	}
	if !ok {
		return Peer{}, fmt.Errorf("untrusted_peer")
	}
	return p, nil
}

func (b *Book) List() ([]Peer, error) {
	var out []Peer
	err := b.st.PrefixScan([]byte(store.PrefixTrust), func(key, value []byte) error {
		var p Peer
		if err := json.Unmarshal(value, &p); err != nil {
			return err
		}
		if p.NodeID != "" {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

func Offer(id identity.Private, role string) Peer {
	return Peer{
		NodeID:       id.Public.NodeID,
		PublicKey:    id.Public.KeyBase64,
		BoxPublicKey: id.Public.BoxKeyBase64,
		Role:         role,
		PairedAt:     time.Now().UTC(),
	}
}
