package interop

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
)

const Schema = "interop/mgmt/v1"

type RecordType string

const (
	TypePresence   RecordType = "presence"
	TypeCapability RecordType = "capability"
	TypeIntentRef  RecordType = "intent_ref"
	TypeAckRef     RecordType = "ack_ref"
)

var allowed = map[RecordType]struct{}{
	TypePresence: {}, TypeCapability: {}, TypeIntentRef: {}, TypeAckRef: {},
}

type Envelope struct {
	Schema          string     `json:"schema"`
	RecordType      RecordType `json:"recordType"`
	OriginNodeID    string     `json:"originNodeID"`
	RecipientNodeID string     `json:"recipientNodeID"`
	OriginSignature string     `json:"originSignature"`
	Ciphertext      string     `json:"ciphertext"`
	CreatedAt       time.Time  `json:"createdAt"`
}

func Wrap(origin identity.Private, recipient identity.Public, recType RecordType, plaintext []byte) (Envelope, error) {
	if _, ok := allowed[recType]; !ok {
		return Envelope{}, fmt.Errorf("interop record type %q is forbidden (management metadata only)", recType)
	}
	if bytes.Contains(bytes.ToLower(plaintext), []byte("password")) {
		return Envelope{}, fmt.Errorf("interop record must not contain password material")
	}
	if bytes.Contains(plaintext, []byte("fse/v1/")) {
		return Envelope{}, fmt.Errorf("interop record must not carry File-Sync-Engine key material")
	}
	ct, err := boxTo(recipient, plaintext)
	if err != nil {
		return Envelope{}, err
	}
	env := Envelope{
		Schema:          Schema,
		RecordType:      recType,
		OriginNodeID:    origin.Public.NodeID,
		RecipientNodeID: recipient.NodeID,
		Ciphertext:      base64.StdEncoding.EncodeToString(ct),
		CreatedAt:       time.Now().UTC(),
	}
	env.OriginSignature = base64.StdEncoding.EncodeToString(origin.Sign(canonical(env)))
	return env, nil
}

func Unwrap(recipient identity.Private, origin identity.Public, env Envelope) ([]byte, error) {
	if env.Schema != Schema {
		return nil, fmt.Errorf("unsupported interop schema %q", env.Schema)
	}
	if _, ok := allowed[env.RecordType]; !ok {
		return nil, fmt.Errorf("forbidden interop record type")
	}
	sig, err := base64.StdEncoding.DecodeString(env.OriginSignature)
	if err != nil {
		return nil, err
	}
	if err := origin.Verify(canonical(env), sig); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	return unbox(recipient, raw)
}

func canonical(env Envelope) []byte {
	copyEnv := env
	copyEnv.OriginSignature = ""
	raw, _ := json.Marshal(copyEnv)
	return raw
}

func boxTo(recipient identity.Public, pt []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	peer, err := recipient.BoxPublic()
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return nil, err
	}
	key, nonce, err := envelopeKey(shared)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, pt, []byte(Schema))
	return append(eph.PublicKey().Bytes(), ct...), nil
}

func unbox(recipient identity.Private, raw []byte) ([]byte, error) {
	if len(raw) < 32 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(raw[:32])
	if err != nil {
		return nil, err
	}
	static, err := recipient.BoxKey()
	if err != nil {
		return nil, err
	}
	shared, err := static.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	key, nonce, err := envelopeKey(shared)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, raw[32:], []byte(Schema))
}

func envelopeKey(shared []byte) (key, nonce []byte, err error) {
	okm := make([]byte, 32+24)
	r := hkdf.Expand(sha256.New, hkdf.Extract(sha256.New, shared, []byte("rmm-interop-box-v1")), []byte(Schema))
	if _, err := io.ReadFull(r, okm); err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], nil
}
