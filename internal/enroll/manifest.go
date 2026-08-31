package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

const Schema = "rmm-enroll-v1"

type Manifest struct {
	Schema             string           `json:"schema"`
	ManifestID         string           `json:"manifestID"`
	EnrollmentID       string           `json:"enrollmentID"`
	IssuerNodeID       string           `json:"issuerNodeID"`
	IssuerPublicKey    string           `json:"issuerPublicKey"`
	IssuerBoxPublicKey string           `json:"issuerBoxPublicKey,omitempty"`
	IssuedAt           time.Time        `json:"issuedAt"`
	ExpiresAt          time.Time        `json:"expiresAt"`
	RevocationID       string           `json:"revocationID"`
	Scope              Scope            `json:"scope"`
	Flags              Flags            `json:"flags"`
	IntendedIdentity   IntendedIdentity `json:"intendedIdentity"`
	TokenHash          string           `json:"tokenHash"`
	Signature          string           `json:"signature,omitempty"`
}

type Scope struct {
	OrgID      string   `json:"orgID"`
	TargetOS   []string `json:"targetOS"`
	TargetArch []string `json:"targetArch"`
	MaxUses    int      `json:"maxUses"`
	Network    Network  `json:"network"`
}

type Network struct {
	BootstrapPeers []BootstrapPeer `json:"bootstrapPeers"`
	AllowDHT       bool            `json:"allowDHT"`
	AllowRelay     bool            `json:"allowRelay"`
	AllowedCIDRs   []string        `json:"allowedCIDRs"`
}

type BootstrapPeer struct {
	NodeID    string `json:"nodeID"`
	PublicKey string `json:"publicKey,omitempty"`
	Address   string `json:"address"`
	Kind      string `json:"kind"`
}

type Flags struct {
	DesktopMode desktop.Mode `json:"desktopMode"`
	SelfUpdate  bool         `json:"selfUpdate"`
}

type IntendedIdentity struct {
	PublisherNodeID       string   `json:"publisherNodeID"`
	PublisherPublicKey    string   `json:"publisherPublicKey"`
	TrustedPeerPublicKeys []string `json:"trustedPeerPublicKeys,omitempty"`
}

type Bundle struct {
	Manifest Manifest
	Token    []byte
}

type Spec struct {
	OrgID          string
	TargetOS       []string
	TargetArch     []string
	MaxUses        int
	TTL            time.Duration
	RevocationID   string
	BootstrapPeers []BootstrapPeer
	AllowDHT       bool
	AllowRelay     bool
	AllowedCIDRs   []string
	DesktopMode    desktop.Mode
	SelfUpdate     bool
	TrustedPeers   []string
}

func Issue(issuer identity.Private, spec Spec) (Bundle, error) {
	if spec.MaxUses < 1 {
		spec.MaxUses = 1
	}
	if spec.TTL <= 0 {
		spec.TTL = 24 * time.Hour
	}
	if spec.DesktopMode == "" {
		spec.DesktopMode = desktop.ModeAuthorizationRequired
	}
	if spec.DesktopMode != desktop.ModeUnattended && spec.DesktopMode != desktop.ModeAuthorizationRequired {
		return Bundle{}, fmt.Errorf("invalid desktop mode flag")
	}
	if err := validateNetwork(spec.AllowedCIDRs, spec.BootstrapPeers, spec.AllowDHT, spec.AllowRelay); err != nil {
		return Bundle{}, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return Bundle{}, err
	}
	sum := sha256.Sum256(token)
	now := time.Now().UTC()
	m := Manifest{
		Schema:             Schema,
		ManifestID:         hex.EncodeToString(sum[:8]) + "-m",
		EnrollmentID:       hex.EncodeToString(sum[8:16]) + "-e",
		IssuerNodeID:       issuer.Public.NodeID,
		IssuerPublicKey:    issuer.Public.KeyBase64,
		IssuerBoxPublicKey: issuer.Public.BoxKeyBase64,
		IssuedAt:           now,
		ExpiresAt:          now.Add(spec.TTL),
		RevocationID:       spec.RevocationID,
		Scope: Scope{
			OrgID:      spec.OrgID,
			TargetOS:   append([]string(nil), spec.TargetOS...),
			TargetArch: append([]string(nil), spec.TargetArch...),
			MaxUses:    spec.MaxUses,
			Network: Network{
				BootstrapPeers: append([]BootstrapPeer(nil), spec.BootstrapPeers...),
				AllowDHT:       spec.AllowDHT,
				AllowRelay:     spec.AllowRelay,
				AllowedCIDRs:   append([]string(nil), spec.AllowedCIDRs...),
			},
		},
		Flags: Flags{DesktopMode: spec.DesktopMode, SelfUpdate: spec.SelfUpdate},
		IntendedIdentity: IntendedIdentity{
			PublisherNodeID:       issuer.Public.NodeID,
			PublisherPublicKey:    issuer.Public.KeyBase64,
			TrustedPeerPublicKeys: append([]string(nil), spec.TrustedPeers...),
		},
		TokenHash: hex.EncodeToString(sum[:]),
	}
	signed, err := Sign(issuer, m)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Manifest: signed, Token: token}, nil
}

func Sign(issuer identity.Private, m Manifest) (Manifest, error) {
	m.IssuerNodeID = issuer.Public.NodeID
	m.IssuerPublicKey = issuer.Public.KeyBase64
	m.Signature = ""
	sig := issuer.Sign(canonical(m))
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return m, nil
}

func Verify(m Manifest) (identity.Public, error) {
	if m.Schema != Schema {
		return identity.Public{}, fmt.Errorf("unsupported enrollment schema")
	}
	pub, err := identity.ParsePublicWithBox(m.IssuerPublicKey, m.IssuerBoxPublicKey)
	if err != nil {
		return identity.Public{}, err
	}
	if pub.NodeID != m.IssuerNodeID {
		return identity.Public{}, fmt.Errorf("issuer node id does not match public key")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return identity.Public{}, err
	}
	copyM := m
	copyM.Signature = ""
	if err := pub.Verify(canonical(copyM), sig); err != nil {
		return identity.Public{}, err
	}
	return pub, nil
}

func VerifyToken(m Manifest, token []byte) error {
	sum := sha256.Sum256(token)
	if hex.EncodeToString(sum[:]) != m.TokenHash {
		return fmt.Errorf("enrollment token does not match manifest")
	}
	return nil
}

func Consume(st store.Store, book *trust.Book, m Manifest, token []byte) error {
	if _, err := Verify(m); err != nil {
		return err
	}
	if time.Now().UTC().After(m.ExpiresAt) {
		return fmt.Errorf("enrollment expired")
	}
	if err := VerifyToken(m, token); err != nil {
		return err
	}
	if revoked, err := IsRevoked(st, m.RevocationID); err != nil {
		return err
	} else if revoked {
		return fmt.Errorf("enrollment revoked")
	}
	if !inList(m.Scope.TargetOS, runtime.GOOS) {
		return fmt.Errorf("enrollment not valid for os %s", runtime.GOOS)
	}
	if !inList(m.Scope.TargetArch, runtime.GOARCH) {
		return fmt.Errorf("enrollment not valid for arch %s", runtime.GOARCH)
	}
	used, err := useCount(st, m.EnrollmentID)
	if err != nil {
		return err
	}
	if used >= m.Scope.MaxUses {
		return fmt.Errorf("enrollment already consumed")
	}
	if err := validateNetwork(m.Scope.Network.AllowedCIDRs, m.Scope.Network.BootstrapPeers, m.Scope.Network.AllowDHT, m.Scope.Network.AllowRelay); err != nil {
		return err
	}
	issuer, err := identity.ParsePublicWithBox(m.IssuerPublicKey, m.IssuerBoxPublicKey)
	if err != nil {
		return err
	}
	if err := book.Add(trust.Peer{NodeID: issuer.NodeID, PublicKey: issuer.KeyBase64, BoxPublicKey: issuer.BoxKeyBase64, Role: "console"}); err != nil {
		return err
	}
	for _, pk := range m.IntendedIdentity.TrustedPeerPublicKeys {
		p, err := identity.ParsePublic(pk)
		if err != nil {
			return err
		}
		if err := book.Add(trust.Peer{NodeID: p.NodeID, PublicKey: p.KeyBase64, Role: "peer"}); err != nil {
			return err
		}
	}
	pol := desktop.Policy{
		Mode:                    m.Flags.DesktopMode,
		InstallAskedOperator:    true,
		UnattendedRequiresProof: m.Flags.DesktopMode != desktop.ModeUnattended,
	}
	if err := desktop.SavePolicy(st, pol); err != nil {
		return err
	}
	rec := map[string]any{
		"enrollmentID": m.EnrollmentID,
		"manifestID":   m.ManifestID,
		"orgID":        m.Scope.OrgID,
		"uses":         used + 1,
		"consumedAt":   time.Now().UTC(),
		"revocationID": m.RevocationID,
		"selfUpdate":   m.Flags.SelfUpdate,
		"desktopMode":  m.Flags.DesktopMode,
	}
	if err := store.PutJSON(st, store.Key(store.PrefixEnroll, "used", m.EnrollmentID), rec); err != nil {
		return err
	}
	return store.PutJSON(st, store.Key(store.PrefixEnroll, "manifest", m.EnrollmentID), m)
}

func Revoke(st store.Store, revocationID string) error {
	if revocationID == "" {
		return fmt.Errorf("revocation id required")
	}
	return store.PutJSON(st, store.Key(store.PrefixEnroll, "revoked", revocationID), map[string]string{"id": revocationID})
}

func IsRevoked(st store.Store, revocationID string) (bool, error) {
	if revocationID == "" {
		return false, nil
	}
	_, ok, err := st.Get(store.Key(store.PrefixEnroll, "revoked", revocationID))
	return ok, err
}

func PolicyText(m Manifest) string {
	var b strings.Builder
	b.WriteString("Decentralized-RMM enrollment policy\n")
	b.WriteString("This is identity-signed enrollment, not merely code signing.\n\n")
	fmt.Fprintf(&b, "Issuer: %s\nOrg: %s\nExpires: %s\nRevocation: %s\nMax uses: %d (one-time/scoped)\n",
		m.IssuerNodeID, m.Scope.OrgID, m.ExpiresAt.UTC().Format(time.RFC3339), m.RevocationID, m.Scope.MaxUses)
	fmt.Fprintf(&b, "Desktop mode: %s\nSelf-update: %v\n", m.Flags.DesktopMode, m.Flags.SelfUpdate)
	fmt.Fprintf(&b, "DHT: %v  Relay: %v\nAllowed CIDRs: %s\n", m.Scope.Network.AllowDHT, m.Scope.Network.AllowRelay, strings.Join(m.Scope.Network.AllowedCIDRs, ", "))
	b.WriteString("Bootstrap peers (scoped, not unrestricted network access):\n")
	for _, p := range m.Scope.Network.BootstrapPeers {
		fmt.Fprintf(&b, "  %s %s %s\n", p.Kind, p.NodeID, p.Address)
	}
	b.WriteString("\nInstallers never contain reusable private keys or passwords.\n")
	return b.String()
}

func AddressAllowed(m Manifest, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("bootstrap address must be an IP in the enrollment CIDR scope")
	}
	if len(m.Scope.Network.AllowedCIDRs) == 0 {
		return fmt.Errorf("enrollment must scope network access with allowedCIDRs")
	}
	for _, c := range m.Scope.Network.AllowedCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("address %s is outside enrollment network scope", addr)
}

func validateNetwork(cidrs []string, peers []BootstrapPeer, allowDHT, allowRelay bool) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("enrollment must not grant unrestricted network access: allowedCIDRs required")
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q", c)
		}
		ones, bits := n.Mask.Size()
		if ones == 0 && bits > 0 {
			return fmt.Errorf("unrestricted CIDR %s is forbidden", c)
		}
	}
	for _, p := range peers {
		if p.Address == "" || p.NodeID == "" {
			return fmt.Errorf("bootstrap peer requires nodeID and address")
		}
		if p.Kind == "relay" && !allowRelay {
			return fmt.Errorf("relay bootstrap peer requires allowRelay")
		}
	}
	_ = allowDHT
	return nil
}

func useCount(st store.Store, enrollmentID string) (int, error) {
	var rec struct {
		Uses int `json:"uses"`
	}
	ok, err := store.GetJSON(st, store.Key(store.PrefixEnroll, "used", enrollmentID), &rec)
	if err != nil || !ok {
		return 0, err
	}
	return rec.Uses, nil
}

func canonical(m Manifest) []byte {
	copyM := m
	copyM.Signature = ""
	sort.Strings(copyM.Scope.TargetOS)
	sort.Strings(copyM.Scope.TargetArch)
	raw, _ := json.Marshal(copyM)
	return raw
}

func inList(list []string, v string) bool {
	if len(list) == 0 {
		return true
	}
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TokenEncode(token []byte) string { return hex.EncodeToString(token) }

func TokenDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
