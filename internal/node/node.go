package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/mesh"
	"github.com/bstone108/Decentralized-RMM/internal/protocol"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

type Role string

const (
	RoleConsole Role = "console"
	RoleAgent   Role = "agent"
	RoleDual    Role = "dual"
)

type Node struct {
	Role   Role
	ID     identity.Private
	Store  store.Store
	Trust  *trust.Book
	Verify desktop.Verifier

	mu               sync.Mutex
	listener         net.Listener
	pendingElevation map[string]*desktop.ElevationProof
}

func Open(st store.Store, role Role, verify desktop.Verifier) (*Node, error) {
	id, err := LoadOrCreateIdentity(st)
	if err != nil {
		return nil, err
	}
	if verify == nil {
		verify = desktop.PasswordVerifier{NoUsablePass: true}
	}
	return &Node{
		Role:             role,
		ID:               id,
		Store:            st,
		Trust:            trust.New(st),
		Verify:           verify,
		pendingElevation: map[string]*desktop.ElevationProof{},
	}, nil
}

func (n *Node) Listen(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	n.mu.Lock()
	n.listener = ln
	n.mu.Unlock()
	go n.acceptLoop()
	return ln.Addr().String(), nil
}

func (n *Node) acceptLoop() {
	for {
		n.mu.Lock()
		ln := n.listener
		n.mu.Unlock()
		if ln == nil {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			sess, err := mesh.Accept(ctx, conn, n.ID, string(n.Role), n.Trust)
			if err != nil {
				_ = conn.Close()
				return
			}
			_ = n.Serve(sess)
			_ = sess.Close()
		}()
	}
}

func (n *Node) Close() error {
	n.mu.Lock()
	ln := n.listener
	n.listener = nil
	n.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (n *Node) Dial(ctx context.Context, addr, expectedNodeID string) (*mesh.Session, error) {
	return mesh.Dial(ctx, addr, n.ID, string(n.Role), n.Trust, expectedNodeID)
}

func (n *Node) Pair(peer trust.Peer) error {
	return n.Trust.Add(peer)
}

func (n *Node) Queue(in intent.Intent) (intent.Intent, error) {
	if in.OriginNodeID == "" {
		in.OriginNodeID = n.ID.Public.NodeID
	}
	if existing, ok, err := intent.LoadByIdempotency(n.Store, in.IdempotencyKey); err != nil {
		return intent.Intent{}, err
	} else if ok {
		return existing, nil
	}
	if proof := extractElevation(&in); proof != nil {
		n.mu.Lock()
		n.pendingElevation[in.ID] = proof
		n.mu.Unlock()
	}
	scrubSecrets(&in)
	in.Status = intent.Queued
	if err := intent.Save(n.Store, in); err != nil {
		return intent.Intent{}, err
	}
	return in, nil
}

func (n *Node) Deliver(sess *mesh.Session, id string) (intent.Receipt, error) {
	in, ok, err := intent.Load(n.Store, id)
	if err != nil {
		return intent.Receipt{}, err
	}
	if !ok {
		return intent.Receipt{}, fmt.Errorf("intent %s not found", id)
	}
	if in.Status == intent.Queued {
		if err := in.Transition(intent.Routed, ""); err != nil {
			return intent.Receipt{}, err
		}
		if err := intent.Save(n.Store, in); err != nil {
			return intent.Receipt{}, err
		}
	}
	wire := in
	n.mu.Lock()
	proof := n.pendingElevation[id]
	delete(n.pendingElevation, id)
	n.mu.Unlock()
	if proof != nil {
		wire.Payload = injectElevation(wire.Payload, proof)
		proof.Zero()
	}
	if err := sess.Send(protocol.Message{Type: protocol.TypeIntent, Intent: &wire}); err != nil {
		return intent.Receipt{}, err
	}
	msg, err := sess.Recv()
	if err != nil {
		return intent.Receipt{}, err
	}
	if msg.Type != protocol.TypeIntentAck || msg.IntentAck == nil {
		return intent.Receipt{}, fmt.Errorf("expected intent_ack, got %s", msg.Type)
	}
	ack := *msg.IntentAck
	in.Status = intent.Acknowledged
	in.LastError = ack.LastError
	in.UpdatedAt = ack.UpdatedAt
	if err := intent.Save(n.Store, in); err != nil {
		return intent.Receipt{}, err
	}
	if err := intent.SaveReceipt(n.Store, ack); err != nil {
		return intent.Receipt{}, err
	}
	n.audit(in, ack.Summary)
	return ack, nil
}

func (n *Node) Serve(sess *mesh.Session) error {
	msg, err := sess.Recv()
	if err != nil {
		return err
	}
	if msg.Type != protocol.TypeIntent || msg.Intent == nil {
		return fmt.Errorf("expected intent")
	}
	applied, receipt, err := n.HandleIntent(*msg.Intent)
	if err != nil && receipt.IntentID == "" {
		return err
	}
	_ = applied
	return sess.Send(protocol.Message{Type: protocol.TypeIntentAck, IntentAck: &receipt})
}

func (n *Node) HandleIntent(in intent.Intent) (intent.Intent, intent.Receipt, error) {
	proof := extractElevation(&in)
	if proof != nil {
		defer proof.Zero()
	}
	scrubSecrets(&in)
	if existing, ok, err := intent.Load(n.Store, in.ID); err != nil {
		return in, intent.Receipt{}, err
	} else if ok && existing.Status.TerminalTarget() {
		rec, recOK, recErr := intent.LoadReceipt(n.Store, in.ID)
		if recErr != nil {
			return existing, rec, recErr
		}
		if recOK {
			return existing, rec, nil
		}
		return existing, existing.Receipt("idempotent replay", nil), nil
	}
	if in.TargetNodeID != n.ID.Public.NodeID && n.Role != RoleDual {
		in.Status = intent.Received
		_ = in.Transition(intent.Failed, "intent target mismatch")
		_ = intent.Save(n.Store, in)
		return in, in.Receipt("target mismatch", nil), fmt.Errorf("target mismatch")
	}
	in.Status = intent.Queued
	if err := in.Transition(intent.Routed, ""); err != nil {
		return in, intent.Receipt{}, err
	}
	if err := in.Transition(intent.Received, ""); err != nil {
		return in, intent.Receipt{}, err
	}
	if err := intent.Save(n.Store, in); err != nil {
		return in, intent.Receipt{}, err
	}
	if err := intent.ValidateSchema(in); err != nil {
		_ = in.Transition(intent.Failed, err.Error())
		_ = intent.Save(n.Store, in)
		rec := in.Receipt("validation failed", nil)
		_ = intent.SaveReceipt(n.Store, rec)
		n.audit(in, rec.Summary)
		return in, rec, nil
	}
	if err := in.Transition(intent.Validated, ""); err != nil {
		return in, intent.Receipt{}, err
	}
	if err := in.Transition(intent.Applying, ""); err != nil {
		return in, intent.Receipt{}, err
	}
	if err := intent.Save(n.Store, in); err != nil {
		return in, intent.Receipt{}, err
	}
	result, summary, applyErr := applyIntent(n, in, proof)
	if applyErr != nil {
		_ = in.Transition(intent.Failed, applyErr.Error())
		_ = intent.Save(n.Store, in)
		rec := in.Receipt(summary, nil)
		_ = intent.SaveReceipt(n.Store, rec)
		n.audit(in, rec.Summary)
		return in, rec, nil
	}
	if err := in.Transition(intent.Succeeded, ""); err != nil {
		return in, intent.Receipt{}, err
	}
	if err := intent.Save(n.Store, in); err != nil {
		return in, intent.Receipt{}, err
	}
	rec := in.Receipt(summary, result)
	_ = intent.SaveReceipt(n.Store, rec)
	n.audit(in, rec.Summary)
	return in, rec, nil
}

func (n *Node) audit(in intent.Intent, summary string) {
	_ = intent.AppendAudit(n.Store, intent.AuditEvent{
		IntentID:     in.ID,
		Kind:         in.Kind,
		Status:       in.Status,
		ActorNodeID:  n.ID.Public.NodeID,
		TargetNodeID: in.TargetNodeID,
		Summary:      summary,
		LastError:    in.LastError,
	})
}

func extractElevation(in *intent.Intent) *desktop.ElevationProof {
	if in.Kind != intent.KindDesktopModeChange || len(in.Payload) == 0 {
		return nil
	}
	var p struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(in.Payload, &p); err != nil || p.Password == "" {
		return nil
	}
	return desktop.NewRemoteProof(p.Username, []byte(p.Password))
}

func scrubSecrets(in *intent.Intent) {
	if in == nil || len(in.Payload) == 0 {
		return
	}
	var p map[string]any
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		in.Payload = nil
		return
	}
	delete(p, "password")
	delete(p, "passwd")
	delete(p, "secret")
	raw, err := json.Marshal(p)
	if err != nil {
		in.Payload = nil
		return
	}
	in.Payload = raw
}

func injectElevation(payload json.RawMessage, proof *desktop.ElevationProof) json.RawMessage {
	var p map[string]any
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &p)
	}
	if p == nil {
		p = map[string]any{}
	}
	if proof.Username != "" {
		p["username"] = proof.Username
	}
	p["password"] = string(proof.Password)
	raw, _ := json.Marshal(p)
	return raw
}
