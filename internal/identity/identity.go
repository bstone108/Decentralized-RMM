package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
)

const NodeIDPrefix = "rmm1:"

// Private is a long-term Ed25519 identity. The private seed must never enter
// interop records, receipts, or logs.
type Private struct {
	Public Public
	seed   ed25519.PrivateKey
}

type Public struct {
	NodeID       string
	Key          ed25519.PublicKey
	KeyBase64    string
	BoxKeyBase64 string
}

func Generate() (Private, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Private{}, err
	}
	return fromKeys(pub, priv), nil
}

func FromSeed(seed ed25519.PrivateKey) (Private, error) {
	if len(seed) != ed25519.PrivateKeySize {
		return Private{}, fmt.Errorf("ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	return fromKeys(seed.Public().(ed25519.PublicKey), seed), nil
}

func ParsePublic(keyBase64 string) (Public, error) {
	return ParsePublicWithBox(keyBase64, "")
}

func ParsePublicWithBox(keyBase64, boxBase64 string) (Public, error) {
	raw, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return Public{}, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return Public{}, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	id, err := Fingerprint(raw)
	if err != nil {
		return Public{}, err
	}
	return Public{NodeID: id, Key: ed25519.PublicKey(raw), KeyBase64: keyBase64, BoxKeyBase64: boxBase64}, nil
}

func BoxPrivate(seed ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	if len(seed) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	sum := sha512.Sum512(seed.Seed())
	var sk [32]byte
	copy(sk[:], sum[:32])
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	return ecdh.X25519().NewPrivateKey(sk[:])
}

func Fingerprint(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	sum := sha256.Sum256(pub)
	return NodeIDPrefix + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (p Private) Sign(message []byte) []byte {
	return ed25519.Sign(p.seed, message)
}

func (p Public) Verify(message, signature []byte) error {
	if !ed25519.Verify(p.Key, message, signature) {
		return fmt.Errorf("identity signature verification failed")
	}
	return nil
}

func (p Private) SeedBase64() string {
	return base64.StdEncoding.EncodeToString(p.seed)
}

func ParseSeed(seedBase64 string) (Private, error) {
	raw, err := base64.StdEncoding.DecodeString(seedBase64)
	if err != nil {
		return Private{}, fmt.Errorf("decode private key: %w", err)
	}
	return FromSeed(raw)
}

func ValidNodeID(id string) bool {
	return strings.HasPrefix(id, NodeIDPrefix) && len(id) > len(NodeIDPrefix)
}

func (p Private) BoxKey() (*ecdh.PrivateKey, error) {
	return BoxPrivate(p.seed)
}

func (p Public) BoxPublic() (*ecdh.PublicKey, error) {
	if p.BoxKeyBase64 == "" {
		return nil, fmt.Errorf("peer box public key is required")
	}
	raw, err := base64.StdEncoding.DecodeString(p.BoxKeyBase64)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(raw)
}

func fromKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey) Private {
	id, _ := Fingerprint(pub)
	boxPub := ""
	if bp, err := BoxPrivate(priv); err == nil {
		boxPub = base64.StdEncoding.EncodeToString(bp.PublicKey().Bytes())
	}
	return Private{
		Public: Public{
			NodeID:       id,
			Key:          append(ed25519.PublicKey(nil), pub...),
			KeyBase64:    base64.StdEncoding.EncodeToString(pub),
			BoxKeyBase64: boxPub,
		},
		seed: append(ed25519.PrivateKey(nil), priv...),
	}
}
