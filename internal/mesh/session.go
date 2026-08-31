package mesh

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/protocol"
	"github.com/bstone108/Decentralized-RMM/internal/sesscrypt"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

type Session struct {
	Conn       net.Conn
	Local      identity.Private
	Remote     identity.Public
	RemoteRole string
	mu         sync.Mutex
	keys       sesscrypt.DirectionKeys
	sendN      uint64
	recvN      uint64
}

func Dial(ctx context.Context, addr string, local identity.Private, role string, book *trust.Book, expectedNodeID string) (*Session, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	s, err := handshakeOutbound(ctx, conn, local, role, book, expectedNodeID)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return s, nil
}

func Accept(ctx context.Context, conn net.Conn, local identity.Private, role string, book *trust.Book) (*Session, error) {
	return handshakeInbound(ctx, conn, local, role, book)
}

func handshakeOutbound(ctx context.Context, conn net.Conn, local identity.Private, role string, book *trust.Book, expected string) (*Session, error) {
	_ = conn.SetDeadline(deadline(ctx, 10*time.Second))
	ephemeral, hello, err := buildHello(local, role)
	if err != nil {
		return nil, err
	}
	if err := writePlain(conn, protocol.Message{Type: protocol.TypeHello, Hello: &hello}); err != nil {
		return nil, err
	}
	msg, err := readPlain(conn)
	if err != nil {
		return nil, err
	}
	if msg.Type == protocol.TypeError {
		return nil, fmt.Errorf("peer error %s: %s", msg.Error.Code, msg.Error.Message)
	}
	if msg.Type != protocol.TypeHello || msg.Hello == nil {
		return nil, fmt.Errorf("expected hello")
	}
	return finish(conn, local, book, expected, ephemeral, hello, *msg.Hello)
}

func handshakeInbound(ctx context.Context, conn net.Conn, local identity.Private, role string, book *trust.Book) (*Session, error) {
	_ = conn.SetDeadline(deadline(ctx, 10*time.Second))
	msg, err := readPlain(conn)
	if err != nil {
		return nil, err
	}
	if msg.Type != protocol.TypeHello || msg.Hello == nil {
		return nil, fmt.Errorf("expected hello")
	}
	pub, err := protocol.VerifyHello(*msg.Hello)
	if err != nil {
		_ = writePlain(conn, errMsg("invalid_hello", "hello verification failed"))
		return nil, err
	}
	if _, err := book.Require(pub.NodeID); err != nil {
		_ = writePlain(conn, errMsg("untrusted_peer", "discovery grants nothing; pair first"))
		return nil, err
	}
	ephemeral, hello, err := buildHello(local, role)
	if err != nil {
		return nil, err
	}
	if err := writePlain(conn, protocol.Message{Type: protocol.TypeHello, Hello: &hello}); err != nil {
		return nil, err
	}
	return finish(conn, local, book, pub.NodeID, ephemeral, hello, *msg.Hello)
}

func finish(conn net.Conn, local identity.Private, book *trust.Book, expected string, localEph sesscrypt.Ephemeral, localHello, remoteHello protocol.Hello) (*Session, error) {
	pub, err := protocol.VerifyHello(remoteHello)
	if err != nil {
		return nil, err
	}
	if expected != "" && pub.NodeID != expected {
		return nil, fmt.Errorf("peer identity public key mismatch")
	}
	if _, err := book.Require(pub.NodeID); err != nil {
		return nil, err
	}
	if err := sesscrypt.ValidateLevel(remoteHello.EncryptionLevel, false); err != nil {
		return nil, err
	}
	shared, err := sesscrypt.SharedSecret(localEph, remoteHello.SessionPublicKey)
	if err != nil {
		return nil, err
	}
	na, err := base64.StdEncoding.DecodeString(localHello.Nonce)
	if err != nil {
		return nil, err
	}
	nb, err := base64.StdEncoding.DecodeString(remoteHello.Nonce)
	if err != nil {
		return nil, err
	}
	keys, err := sesscrypt.Derive(shared, na, nb, local.Public.NodeID, pub.NodeID)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &Session{
		Conn:       conn,
		Local:      local,
		Remote:     pub,
		RemoteRole: remoteHello.Role,
		keys:       keys,
	}, nil
}

func buildHello(local identity.Private, role string) (sesscrypt.Ephemeral, protocol.Hello, error) {
	eph, err := sesscrypt.GenerateEphemeral()
	if err != nil {
		return sesscrypt.Ephemeral{}, protocol.Hello{}, err
	}
	nonce, err := sesscrypt.RandomNonce(32)
	if err != nil {
		return sesscrypt.Ephemeral{}, protocol.Hello{}, err
	}
	h := protocol.Hello{
		ProtocolVersion:  protocol.Version,
		Role:             role,
		SessionPublicKey: eph.PubB64,
		EncryptionLevel:  sesscrypt.DefaultLevel,
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		Capabilities:     protocol.DefaultCapabilities(),
	}
	signed, err := protocol.SignHello(local, h)
	return eph, signed, err
}

func (s *Session) Send(msg protocol.Message) error {
	raw, err := protocol.Encode(msg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendN++
	ct, err := sesscrypt.Seal(s.keys.Send, s.keys.SendPrefix, s.sendN, raw)
	if err != nil {
		return err
	}
	return protocol.WriteFrame(s.Conn, ct)
}

func (s *Session) Recv() (protocol.Message, error) {
	ct, err := protocol.ReadFrame(s.Conn)
	if err != nil {
		return protocol.Message{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recvN++
	pt, err := sesscrypt.Open(s.keys.Recv, s.keys.RecvPrefix, s.recvN, ct)
	if err != nil {
		return protocol.Message{}, err
	}
	return protocol.Decode(pt)
}

func (s *Session) Close() error { return s.Conn.Close() }

func writePlain(conn net.Conn, msg protocol.Message) error {
	raw, err := protocol.Encode(msg)
	if err != nil {
		return err
	}
	return protocol.WriteFrame(conn, raw)
}

func readPlain(conn net.Conn) (protocol.Message, error) {
	raw, err := protocol.ReadFrame(conn)
	if err != nil {
		return protocol.Message{}, err
	}
	return protocol.Decode(raw)
}

func errMsg(code, message string) protocol.Message {
	return protocol.Message{Type: protocol.TypeError, Error: &protocol.Error{Code: code, Message: message}}
}

func deadline(ctx context.Context, d time.Duration) time.Time {
	if t, ok := ctx.Deadline(); ok {
		return t
	}
	return time.Now().Add(d)
}
