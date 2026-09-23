package protocol

import (
	"bytes"
	"testing"

	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/sesscrypt"
)

func TestFrameRoundTripAndCap(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte(`{"type":"error","error":{"code":"x","message":"y"}}`)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil || !bytes.Contains(got, []byte("error")) {
		t.Fatalf("%s %v", got, err)
	}
	if err := WriteFrame(&buf, make([]byte, MaxMessageBytes+1)); err == nil {
		t.Fatal("expected cap")
	}
}

func TestSignedHello(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := sesscrypt.RandomNonce(32)
	h := Hello{
		ProtocolVersion:  Version,
		Role:             "agent",
		SessionPublicKey: "sess",
		EncryptionLevel:  4,
		Nonce:            string(nonce),
		Capabilities:     DefaultCapabilities(),
	}
	signed, err := SignHello(id, h)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := VerifyHello(signed)
	if err != nil {
		t.Fatal(err)
	}
	if pub.NodeID != id.Public.NodeID {
		t.Fatal(pub.NodeID)
	}
	signed.Role = "console"
	if _, err := VerifyHello(signed); err == nil {
		t.Fatal("tampered role must fail")
	}
}

func TestUnknownTypeRejected(t *testing.T) {
	if _, err := Decode([]byte(`{"type":"block_request"}`)); err == nil {
		t.Fatal("fse message type must not be accepted")
	}
}

func TestArtifactMessagesRoundTrip(t *testing.T) {
	raw, err := Encode(Message{Type: TypeArtifactRequest, ArtifactRequest: &ArtifactRequest{
		Component: "rmm-agent", Version: "1.0.0", GOOS: "linux", GOARCH: "amd64",
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil || got.ArtifactRequest.Component != "rmm-agent" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := Encode(Message{Type: TypeArtifactOffer, ArtifactOffer: &ArtifactOffer{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Encode(Message{Type: TypeArtifactChunk, ArtifactChunk: &ArtifactChunk{Data: []byte("x"), Last: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Encode(Message{Type: TypeEnrollmentRevoke, EnrollmentRevoke: &enroll.RevocationNotice{GrantID: "grant:x"}}); err != nil {
		t.Fatal(err)
	}
}
