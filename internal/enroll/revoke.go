package enroll

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

const RevokeSchema = "rmm-enroll-revoke-v1"

const (
	ReasonRevoked = "revoked"
	ReasonRetired = "retired"
)

// RevocationNotice is an issuer-signed publication that a grant may no longer
// be used. Historic receipts and audit records are retained.
type RevocationNotice struct {
	Schema          string    `json:"schema"`
	GrantID         string    `json:"grantID"`
	Reason          string    `json:"reason"`
	IssuerNodeID    string    `json:"issuerNodeID"`
	IssuerPublicKey string    `json:"issuerPublicKey"`
	IssuedAt        time.Time `json:"issuedAt"`
	Signature       string    `json:"signature,omitempty"`
}

func SignRevocation(issuer identity.Private, grantID, reason string) (RevocationNotice, error) {
	if grantID == "" {
		return RevocationNotice{}, fmt.Errorf("grant id required")
	}
	if reason != ReasonRevoked && reason != ReasonRetired {
		return RevocationNotice{}, fmt.Errorf("reason must be revoked or retired")
	}
	n := RevocationNotice{
		Schema:          RevokeSchema,
		GrantID:         grantID,
		Reason:          reason,
		IssuerNodeID:    issuer.Public.NodeID,
		IssuerPublicKey: issuer.Public.KeyBase64,
		IssuedAt:        time.Now().UTC(),
	}
	sig := issuer.Sign(revokeCanonical(n))
	n.Signature = base64.StdEncoding.EncodeToString(sig)
	return n, nil
}

func VerifyRevocation(n RevocationNotice) (identity.Public, error) {
	if n.Schema != RevokeSchema {
		return identity.Public{}, fmt.Errorf("unsupported revocation schema")
	}
	if n.GrantID == "" {
		return identity.Public{}, fmt.Errorf("grant id required")
	}
	pub, err := identity.ParsePublic(n.IssuerPublicKey)
	if err != nil {
		return identity.Public{}, err
	}
	if pub.NodeID != n.IssuerNodeID {
		return identity.Public{}, fmt.Errorf("revocation issuer id does not match public key")
	}
	sig, err := base64.StdEncoding.DecodeString(n.Signature)
	if err != nil {
		return identity.Public{}, err
	}
	copyN := n
	copyN.Signature = ""
	if err := pub.Verify(revokeCanonical(copyN), sig); err != nil {
		return identity.Public{}, err
	}
	return pub, nil
}

func revokeCanonical(n RevocationNotice) []byte {
	copyN := n
	copyN.Signature = ""
	raw, _ := json.Marshal(copyN)
	return raw
}

func revokeKey(grantID string) []byte {
	return store.Key(store.PrefixEnroll, "revoked", grantID)
}

// ApplyRevocation stores a verified notice and prevents future enrollments.
// Receipts and audit history are not deleted.
func ApplyRevocation(st store.Store, book *trust.Book, n RevocationNotice) error {
	pub, err := VerifyRevocation(n)
	if err != nil {
		return err
	}
	if book != nil {
		if ok, err := book.Trusted(pub.NodeID); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("untrusted_peer")
		}
	}
	if err := store.PutJSON(st, revokeKey(n.GrantID), n); err != nil {
		return err
	}
	return intent.AppendAudit(st, intent.AuditEvent{
		IntentID:    "enroll-revoke:" + n.GrantID,
		Kind:        "enrollment.revoke",
		Status:      intent.Succeeded,
		ActorNodeID: n.IssuerNodeID,
		Summary:     fmt.Sprintf("grant %s %s; historic enrollment receipts retained", n.GrantID, n.Reason),
	})
}

func Revoke(st store.Store, grantID string) error {
	if grantID == "" {
		return fmt.Errorf("grant id required")
	}
	return store.PutJSON(st, revokeKey(grantID), map[string]string{"id": grantID, "reason": ReasonRevoked})
}

func IsRevoked(st store.Store, grantID string) (bool, error) {
	if grantID == "" {
		return false, nil
	}
	_, ok, err := st.Get(revokeKey(grantID))
	return ok, err
}
