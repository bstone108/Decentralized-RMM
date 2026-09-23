package sesscrypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	DefaultLevel = 4
	OKMSize      = 80
	InfoSession  = "rmm-session-v1"
	InfoNonceCS  = "rmm-nonce-v1-cs"
	InfoNonceSC  = "rmm-nonce-v1-sc"
)

type Ephemeral struct {
	Private *ecdh.PrivateKey
	Public  []byte
	PubB64  string
}

func GenerateEphemeral() (Ephemeral, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Ephemeral{}, err
	}
	pub := priv.PublicKey().Bytes()
	return Ephemeral{
		Private: priv,
		Public:  pub,
		PubB64:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

func SharedSecret(local Ephemeral, peerPubB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("session public key: %w", err)
	}
	peer, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("session public key: %w", err)
	}
	return local.Private.ECDH(peer)
}

type DirectionKeys struct {
	Send       []byte
	Recv       []byte
	SendPrefix [16]byte
	RecvPrefix [16]byte
}

func Derive(shared, nonceA, nonceB []byte, localID, remoteID string) (DirectionKeys, error) {
	var salt []byte
	if bytes.Compare(nonceA, nonceB) <= 0 {
		salt = append(append([]byte{}, nonceA...), nonceB...)
	} else {
		salt = append(append([]byte{}, nonceB...), nonceA...)
	}
	prk := hkdf.Extract(sha256.New, shared, salt)
	okm := make([]byte, OKMSize)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte(InfoSession)), okm); err != nil {
		return DirectionKeys{}, err
	}
	kCS := okm[0:32]
	kSC := okm[32:64]
	var keys DirectionKeys
	if localID < remoteID {
		keys.Send = append([]byte(nil), kCS...)
		keys.Recv = append([]byte(nil), kSC...)
		if err := fillPrefix(&keys.SendPrefix, prk, InfoNonceCS); err != nil {
			return DirectionKeys{}, err
		}
		if err := fillPrefix(&keys.RecvPrefix, prk, InfoNonceSC); err != nil {
			return DirectionKeys{}, err
		}
	} else {
		keys.Send = append([]byte(nil), kSC...)
		keys.Recv = append([]byte(nil), kCS...)
		if err := fillPrefix(&keys.SendPrefix, prk, InfoNonceSC); err != nil {
			return DirectionKeys{}, err
		}
		if err := fillPrefix(&keys.RecvPrefix, prk, InfoNonceCS); err != nil {
			return DirectionKeys{}, err
		}
	}
	return keys, nil
}

func Seal(key []byte, prefix [16]byte, counter uint64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce(prefix, counter), plaintext, nil), nil
}

func Open(key []byte, prefix [16]byte, counter uint64, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce(prefix, counter), ciphertext, nil)
}

func nonce(prefix [16]byte, counter uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSizeX)
	copy(n[:16], prefix[:])
	binary.BigEndian.PutUint64(n[16:], counter)
	return n
}

func fillPrefix(dst *[16]byte, prk []byte, info string) error {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte(info)), buf); err != nil {
		return err
	}
	copy(dst[:], buf)
	return nil
}

func RandomNonce(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func ValidateLevel(level int, allowDebug bool) error {
	if level == 0 && allowDebug {
		return nil
	}
	if level < DefaultLevel || level > 7 {
		return fmt.Errorf("encryption level %d is not accepted (need 4-7)", level)
	}
	return nil
}
