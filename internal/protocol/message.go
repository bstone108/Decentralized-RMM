package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
)

const Version = 1

type Type string

const (
	TypeHello           Type = "hello"
	TypeError           Type = "error"
	TypeIntent          Type = "intent"
	TypeIntentAck       Type = "intent_ack"
	TypeInventory       Type = "inventory"
	TypePeerExchange    Type = "peer_exchange"
	TypeDesktopRequest  Type = "desktop_request"
	TypeDesktopDecision Type = "desktop_decision"
	TypeInteropRecord   Type = "interop_record"
	TypeArtifactOffer   Type = "artifact_offer"
	TypeArtifactRequest Type = "artifact_request"
	TypeArtifactChunk   Type = "artifact_chunk"
)

type Message struct {
	Type            Type             `json:"type"`
	Hello           *Hello           `json:"hello,omitempty"`
	Error           *Error           `json:"error,omitempty"`
	Intent          *intent.Intent   `json:"intent,omitempty"`
	IntentAck       *intent.Receipt  `json:"intentAck,omitempty"`
	Inventory       json.RawMessage  `json:"inventory,omitempty"`
	PeerExchange    *PeerExchange    `json:"peerExchange,omitempty"`
	DesktopRequest  *DesktopRequest  `json:"desktopRequest,omitempty"`
	DesktopDecision *DesktopDecision `json:"desktopDecision,omitempty"`
	InteropRecord   json.RawMessage  `json:"interopRecord,omitempty"`
	ArtifactOffer   *ArtifactOffer   `json:"artifactOffer,omitempty"`
	ArtifactRequest *ArtifactRequest `json:"artifactRequest,omitempty"`
	ArtifactChunk   *ArtifactChunk   `json:"artifactChunk,omitempty"`
}

type Hello struct {
	ProtocolVersion  int      `json:"protocolVersion"`
	NodeID           string   `json:"nodeID"`
	Role             string   `json:"role"`
	PublicKey        string   `json:"publicKey"`
	SessionPublicKey string   `json:"sessionPublicKey"`
	EncryptionLevel  int      `json:"encryptionLevel"`
	Nonce            string   `json:"nonce"`
	Capabilities     []string `json:"capabilities,omitempty"`
	Signature        string   `json:"signature"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type PeerExchange struct {
	Peers []PeerCandidate `json:"peers"`
}

type PeerCandidate struct {
	NodeID    string   `json:"nodeID"`
	Addresses []string `json:"addresses"`
}

type DesktopRequest struct {
	ViewerNodeID string `json:"viewerNodeID"`
	Mode         string `json:"mode"`
	IntentID     string `json:"intentID"`
}

type DesktopDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Mode    string `json:"mode"`
}

// ArtifactOffer advertises cached signed release metadata. Payload bytes are
// never implied trusted; each recipient verifies independently.
type ArtifactOffer struct {
	Artifacts []ArtifactMeta `json:"artifacts"`
}

type ArtifactMeta struct {
	Component       string `json:"component"`
	Version         string `json:"version"`
	GOOS            string `json:"goos"`
	GOARCH          string `json:"goarch"`
	SHA256          string `json:"sha256"`
	Size            int    `json:"size"`
	PublisherNodeID string `json:"publisherNodeID"`
}

type ArtifactRequest struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
}

// ArtifactChunk is one independently framed slice of a signed envelope.
type ArtifactChunk struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	SHA256    string `json:"sha256"`
	Offset    int    `json:"offset"`
	Total     int    `json:"total"`
	Data      []byte `json:"data"`
	Last      bool   `json:"last"`
}

func (m Message) Validate() error {
	switch m.Type {
	case TypeHello:
		if m.Hello == nil {
			return fmt.Errorf("hello payload required")
		}
	case TypeError:
		if m.Error == nil || m.Error.Code == "" {
			return fmt.Errorf("error payload required")
		}
	case TypeIntent:
		if m.Intent == nil {
			return fmt.Errorf("intent payload required")
		}
	case TypeIntentAck:
		if m.IntentAck == nil {
			return fmt.Errorf("intent ack payload required")
		}
	case TypeInventory:
		if len(m.Inventory) == 0 {
			return fmt.Errorf("inventory payload required")
		}
	case TypePeerExchange:
		if m.PeerExchange == nil {
			return fmt.Errorf("peer exchange payload required")
		}
	case TypeDesktopRequest:
		if m.DesktopRequest == nil {
			return fmt.Errorf("desktop request payload required")
		}
	case TypeDesktopDecision:
		if m.DesktopDecision == nil {
			return fmt.Errorf("desktop decision payload required")
		}
	case TypeInteropRecord:
		if len(m.InteropRecord) == 0 {
			return fmt.Errorf("interop record payload required")
		}
	case TypeArtifactOffer:
		if m.ArtifactOffer == nil {
			return fmt.Errorf("artifact offer payload required")
		}
	case TypeArtifactRequest:
		if m.ArtifactRequest == nil || m.ArtifactRequest.Component == "" {
			return fmt.Errorf("artifact request payload required")
		}
	case TypeArtifactChunk:
		if m.ArtifactChunk == nil {
			return fmt.Errorf("artifact chunk payload required")
		}
	default:
		return fmt.Errorf("unknown message type %q", m.Type)
	}
	return nil
}

func Encode(m Message) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func Decode(raw []byte) (Message, error) {
	var m Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return Message{}, err
	}
	return m, m.Validate()
}

func HelloTranscript(h Hello) []byte {
	caps := append([]string(nil), h.Capabilities...)
	sort.Strings(caps)
	var b bytes.Buffer
	b.WriteString("rmm-hello-v1\n")
	b.WriteString(h.NodeID)
	b.WriteByte('\n')
	b.WriteString(h.Role)
	b.WriteByte('\n')
	b.WriteString(h.PublicKey)
	b.WriteByte('\n')
	b.WriteString(h.SessionPublicKey)
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(h.EncryptionLevel))
	b.WriteByte('\n')
	b.WriteString(h.Nonce)
	b.WriteByte('\n')
	b.WriteString(strings.Join(caps, ","))
	return b.Bytes()
}

func SignHello(id identity.Private, h Hello) (Hello, error) {
	h.NodeID = id.Public.NodeID
	h.PublicKey = id.Public.KeyBase64
	sig := id.Sign(HelloTranscript(h))
	h.Signature = base64.StdEncoding.EncodeToString(sig)
	return h, nil
}

func VerifyHello(h Hello) (identity.Public, error) {
	if h.ProtocolVersion != Version {
		return identity.Public{}, fmt.Errorf("protocol version %d not supported", h.ProtocolVersion)
	}
	pub, err := identity.ParsePublic(h.PublicKey)
	if err != nil {
		return identity.Public{}, err
	}
	if pub.NodeID != h.NodeID {
		return identity.Public{}, fmt.Errorf("hello node id does not match public key")
	}
	sig, err := base64.StdEncoding.DecodeString(h.Signature)
	if err != nil {
		return identity.Public{}, fmt.Errorf("hello signature: %w", err)
	}
	if err := pub.Verify(HelloTranscript(h), sig); err != nil {
		return identity.Public{}, err
	}
	return pub, nil
}

func DefaultCapabilities() []string {
	return []string{
		"intent.v1", "inventory.v1", "desktop.v1", "interop.mgmt.v1",
		"artifact.cache.v1", "dht.candidates.v1",
	}
}
