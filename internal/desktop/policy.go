package desktop

import (
	"fmt"
	"runtime"

	"github.com/bstone108/Decentralized-RMM/internal/store"
)

type Mode string

const (
	ModeUnattended            Mode = "unattended"
	ModeAuthorizationRequired Mode = "authorization-required"
)

type Policy struct {
	Mode                    Mode `json:"mode"`
	CaptureGrantPresent     bool `json:"captureGrantPresent,omitempty"`
	InstallAskedOperator    bool `json:"installAskedOperator"`
	UnattendedRequiresProof bool `json:"unattendedRequiresProof"`
}

func DefaultPolicy() Policy {
	return Policy{
		Mode:                    ModeAuthorizationRequired,
		InstallAskedOperator:    false,
		UnattendedRequiresProof: true,
	}
}

func PolicyKey() []byte { return store.Key(store.PrefixDesktop, "policy") }

func LoadPolicy(st store.Store) (Policy, error) {
	var p Policy
	ok, err := store.GetJSON(st, PolicyKey(), &p)
	if err != nil {
		return Policy{}, err
	}
	if !ok {
		return DefaultPolicy(), nil
	}
	return p, nil
}

func SavePolicy(st store.Store, p Policy) error {
	if p.Mode != ModeUnattended && p.Mode != ModeAuthorizationRequired {
		return fmt.Errorf("invalid desktop mode %q", p.Mode)
	}
	return store.PutJSON(st, PolicyKey(), p)
}

// ElevationProof is an ephemeral admin/root secret. Zero must be called.
type ElevationProof struct {
	Username     string
	Password     []byte
	LocalAccess  bool
	remoteCaller bool
}

func NewRemoteProof(username string, password []byte) *ElevationProof {
	p := append([]byte(nil), password...)
	return &ElevationProof{Username: username, Password: p, remoteCaller: true}
}

func NewLocalAccess() *ElevationProof {
	return &ElevationProof{LocalAccess: true}
}

func (p *ElevationProof) Zero() {
	if p == nil {
		return
	}
	for i := range p.Password {
		p.Password[i] = 0
	}
	p.Password = nil
	p.Username = ""
}

func (p *ElevationProof) RemoteCaller() bool {
	return p != nil && p.remoteCaller
}

type Verifier interface {
	Verify(proof *ElevationProof) error
}

// PasswordVerifier is a test double. Production wires PAM/WinLogon/Directory.
type PasswordVerifier struct {
	ExpectedUser string
	ExpectedPass []byte
	NoUsablePass bool
}

func (v PasswordVerifier) Verify(proof *ElevationProof) error {
	if proof != nil && proof.LocalAccess && !proof.RemoteCaller() {
		return nil
	}
	if v.NoUsablePass {
		return fmt.Errorf("no usable admin password exists; direct local access is required")
	}
	if proof == nil || len(proof.Password) == 0 {
		return fmt.Errorf("admin proof required to enable unattended desktop")
	}
	if v.ExpectedUser != "" && proof.Username != v.ExpectedUser {
		return fmt.Errorf("admin proof rejected")
	}
	if string(proof.Password) != string(v.ExpectedPass) {
		return fmt.Errorf("admin proof rejected")
	}
	return nil
}

type SessionRequest struct {
	ViewerNodeID string
	Mode         Mode
	HasLocalUser bool
	LocalConsent bool
}

func AuthorizeSession(p Policy, req SessionRequest) (allowed bool, reason string) {
	if req.ViewerNodeID == "" {
		return false, "viewer must be an authenticated trusted peer"
	}
	if p.Mode == ModeUnattended {
		return true, "unattended policy allows trusted viewer"
	}
	if !req.HasLocalUser {
		return false, "authorization-required but no interactive session (X11/Wayland/Aqua/Win32)"
	}
	if !req.LocalConsent {
		return false, "target user must authorize this session"
	}
	return true, "interactive authorization granted"
}

func ChangeMode(st store.Store, desired Mode, proof *ElevationProof, verifier Verifier, remote bool) (Policy, error) {
	if proof != nil {
		defer proof.Zero()
	}
	cur, err := LoadPolicy(st)
	if err != nil {
		return Policy{}, err
	}
	if desired == cur.Mode {
		return cur, nil
	}
	if desired == ModeAuthorizationRequired {
		cur.Mode = desired
		if err := SavePolicy(st, cur); err != nil {
			return Policy{}, err
		}
		return cur, nil
	}
	if desired != ModeUnattended {
		return Policy{}, fmt.Errorf("invalid desktop mode %q", desired)
	}
	if remote && proof != nil && proof.LocalAccess {
		return Policy{}, fmt.Errorf("remote callers cannot assert localAccess")
	}
	if verifier == nil {
		verifier = PasswordVerifier{NoUsablePass: true}
	}
	if err := verifier.Verify(proof); err != nil {
		return Policy{}, err
	}
	cur.Mode = ModeUnattended
	if err := SavePolicy(st, cur); err != nil {
		return Policy{}, err
	}
	return cur, nil
}

func DisplayHint() string {
	switch runtime.GOOS {
	case "linux":
		return "x11-or-wayland"
	case "darwin":
		return "aqua"
	case "windows":
		return "win32"
	default:
		return runtime.GOOS
	}
}
