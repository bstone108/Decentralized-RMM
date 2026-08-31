package node

import (
	"encoding/json"
	"fmt"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

type persistedIdentity struct {
	Seed         string `json:"seed"`
	PublicKey    string `json:"publicKey"`
	BoxPublicKey string `json:"boxPublicKey"`
	NodeID       string `json:"nodeID"`
}

func identityKey() []byte { return store.Key(store.PrefixPrivate, "identity") }

func LoadOrCreateIdentity(st store.Store) (identity.Private, error) {
	var rec persistedIdentity
	ok, err := store.GetJSON(st, identityKey(), &rec)
	if err != nil {
		return identity.Private{}, err
	}
	if ok {
		return identity.ParseSeed(rec.Seed)
	}
	id, err := identity.Generate()
	if err != nil {
		return identity.Private{}, err
	}
	if err := SaveIdentity(st, id); err != nil {
		return identity.Private{}, err
	}
	return id, nil
}

func SaveIdentity(st store.Store, id identity.Private) error {
	return store.PutJSON(st, identityKey(), persistedIdentity{
		Seed:         id.SeedBase64(),
		PublicKey:    id.Public.KeyBase64,
		BoxPublicKey: id.Public.BoxKeyBase64,
		NodeID:       id.Public.NodeID,
	})
}

func MustNodeID(id identity.Private) string {
	if id.Public.NodeID == "" {
		return fmt.Sprintf("invalid")
	}
	return id.Public.NodeID
}

func marshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
