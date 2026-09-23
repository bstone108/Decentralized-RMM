package consolegui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/consolemesh"
	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/node"
)

// Status is what the native GUI must show for authenticated mesh presence.
type Status struct {
	ConsoleNodeID     string           `json:"consoleNodeID"`
	MeshMode          consolemesh.Mode `json:"meshMode"`
	PrefersLocalAgent bool             `json:"prefersLocalAgent"`
	Authenticated     bool             `json:"authenticated"`
	LocalAgentAddr    string           `json:"localAgentAddr,omitempty"`
	LocalAgentNodeID  string           `json:"localAgentNodeID,omitempty"`
	BuiltinMeshAddr   string           `json:"builtinMeshAddr,omitempty"`
	PolicyVisible     bool             `json:"policyVisible"`
	LastAuthorization string           `json:"lastAuthorization,omitempty"`
	LastReceipt       string           `json:"lastReceipt,omitempty"`
	HasAgentFunction  bool             `json:"hasAgentFunction"` // always false
}

// Line is the native GUI status text (authenticated local-agent-preferred mesh).
func (s Status) Line() string {
	return fmt.Sprintf(
		"console %s\nmesh %s\nprefers local agent: %v\nauthenticated: %v\nlocal agent: %s %s\nbuiltin mesh: %s\nagent function: %v\npolicy visible: %v\nlast authorization: %s\nlast receipt: %s",
		s.ConsoleNodeID, s.MeshMode, s.PrefersLocalAgent, s.Authenticated,
		s.LocalAgentNodeID, s.LocalAgentAddr, s.BuiltinMeshAddr,
		s.HasAgentFunction, s.PolicyVisible, s.LastAuthorization, s.LastReceipt,
	)
}

func intentPrompt(p Proposal) string {
	return fmt.Sprintf(
		"Authorize management intent %s on %s?\nThis console will not apply the intent locally.",
		p.Kind, p.TargetNodeID,
	)
}

// Proposal is an operator-requested management intent from the GUI.
type Proposal struct {
	Kind            intent.Kind
	TargetNodeID    string
	Payload         json.RawMessage
	OperatorConfirm bool
	ElevationUser   string
	ElevationPass   []byte // ephemeral; never copied into Status
}

func (p *Proposal) ZeroElevation() {
	if p == nil {
		return
	}
	for i := range p.ElevationPass {
		p.ElevationPass[i] = 0
	}
	p.ElevationPass = nil
	p.ElevationUser = ""
}

// Authorization is the safe workflow gate before Queue/Deliver.
type Authorization struct {
	Allowed                 bool
	Reason                  string
	RequiresOperatorConfirm bool
	RequiresElevation       bool
}

// Session is the GUI console's non-TUI, non-web control plane.
type Session struct {
	Runtime *consolemesh.Runtime
	Policy  string
	status  Status
}

func NewSession(rt *consolemesh.Runtime, policyText string) *Session {
	s := &Session{Runtime: rt, Policy: policyText}
	s.refresh()
	return s
}

func (s *Session) Status() Status {
	s.refresh()
	return s.status
}

func (s *Session) refresh() {
	st := Status{HasAgentFunction: false, PolicyVisible: strings.TrimSpace(s.Policy) != ""}
	if s.Runtime != nil && s.Runtime.Node != nil {
		st.ConsoleNodeID = s.Runtime.Node.ID.Public.NodeID
		st.MeshMode = s.Runtime.Mode
		st.PrefersLocalAgent = s.Runtime.PrefersLocalAgent()
		st.LocalAgentAddr = s.Runtime.LocalAddr
		st.LocalAgentNodeID = s.Runtime.LocalNodeID
		st.BuiltinMeshAddr = s.Runtime.MeshAddr
		st.Authenticated = s.Runtime.Node.Role == node.RoleConsole && (st.PrefersLocalAgent || s.Runtime.Node.HasListener())
	}
	st.LastAuthorization = s.status.LastAuthorization
	st.LastReceipt = s.status.LastReceipt
	s.status = st
}

func (s *Session) DefaultTarget() string {
	if s.Runtime != nil {
		return s.Runtime.LocalNodeID
	}
	return ""
}

func (s *Session) DialAddr() string {
	if s.Runtime != nil {
		return s.Runtime.DialAddr()
	}
	return ""
}

func (s *Session) Authorize(p Proposal) Authorization {
	if s.Runtime == nil || s.Runtime.Node == nil || s.Runtime.Node.Role != node.RoleConsole {
		return Authorization{Reason: "GUI console requires the separately deployable console component"}
	}
	if p.Kind == intent.KindCommandRun {
		return Authorization{Reason: "command.run is disabled until a signed authz policy exists"}
	}
	if p.TargetNodeID == "" {
		return Authorization{Reason: "target node id is required"}
	}
	if p.TargetNodeID == s.Runtime.Node.ID.Public.NodeID {
		return Authorization{Reason: "console has no endpoint-management agent function"}
	}
	if _, err := s.Runtime.Node.Trust.Require(p.TargetNodeID); err != nil {
		return Authorization{Reason: "discovery grants nothing; pair the target before an intent"}
	}
	auth := Authorization{
		Allowed:                 true,
		RequiresOperatorConfirm: true,
		Reason:                  "operator confirmation required",
	}
	if p.Kind == intent.KindDesktopModeChange {
		var body struct {
			Mode desktop.Mode `json:"mode"`
		}
		_ = json.Unmarshal(p.Payload, &body)
		if body.Mode == desktop.ModeUnattended {
			auth.RequiresElevation = true
			auth.Reason = "unattended desktop requires ephemeral admin proof and operator confirmation"
		}
	}
	if !p.OperatorConfirm {
		auth.Allowed = false
		auth.Reason = "operator must confirm this management intent in the GUI"
		s.status.LastAuthorization = auth.Reason
		return auth
	}
	if auth.RequiresElevation && len(p.ElevationPass) == 0 && p.ElevationUser == "" {
		auth.Allowed = false
		auth.Reason = "ephemeral admin proof required for unattended desktop"
		s.status.LastAuthorization = auth.Reason
		return auth
	}
	auth.Reason = fmt.Sprintf("authorized %s to %s over authenticated mesh", p.Kind, p.TargetNodeID)
	s.status.LastAuthorization = auth.Reason
	return auth
}

// Submit runs the authorized intent over the authenticated mesh. The console
// never applies the intent locally.
func (s *Session) Submit(ctx context.Context, p Proposal) (intent.Receipt, error) {
	defer p.ZeroElevation()
	auth := s.Authorize(p)
	if !auth.Allowed {
		return intent.Receipt{}, fmt.Errorf("%s", auth.Reason)
	}
	addr := s.DialAddr()
	if addr == "" {
		return intent.Receipt{}, fmt.Errorf("no authenticated mesh address")
	}
	id := fmt.Sprintf("gui-%d", time.Now().UnixNano())
	payload := append([]byte(nil), p.Payload...)
	if auth.RequiresElevation && len(p.ElevationPass) > 0 {
		body := map[string]any{}
		_ = json.Unmarshal(payload, &body)
		if body == nil {
			body = map[string]any{}
		}
		if p.ElevationUser != "" {
			body["username"] = p.ElevationUser
		}
		body["password"] = string(p.ElevationPass)
		payload, _ = json.Marshal(body)
	}
	queued, err := s.Runtime.Node.Queue(intent.New(id, id, s.Runtime.Node.ID.Public.NodeID, p.TargetNodeID, p.Kind, payload))
	if err != nil {
		return intent.Receipt{}, err
	}
	sess, err := s.Runtime.Node.Dial(ctx, addr, p.TargetNodeID)
	if err != nil {
		return intent.Receipt{}, err
	}
	defer sess.Close()
	ack, err := s.Runtime.Node.Deliver(sess, queued.ID)
	if err != nil {
		return intent.Receipt{}, err
	}
	s.status.LastReceipt = ack.Summary
	return ack, nil
}
