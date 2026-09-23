package enroll

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

type grantCounter struct {
	GrantID string `json:"grantID"`
	Uses    int    `json:"uses"`
}

// UseReceipt is a durable per-use enrollment receipt. Revocation must never
// delete these records.
type UseReceipt struct {
	GrantID        string    `json:"grantID"`
	UseSeq         int       `json:"useSeq"`
	EnrolleeNodeID string    `json:"enrolleeNodeID,omitempty"`
	At             time.Time `json:"at"`
	Mode           UseMode   `json:"mode"`
	AllowedCount   int       `json:"allowedCount,omitempty"`
	ManifestID     string    `json:"manifestID"`
	OrgID          string    `json:"orgID"`
	Summary        string    `json:"summary"`
}

func counterKey(grantID string) []byte {
	return store.Key(store.PrefixEnroll, "grant", grantID, "counter")
}

func receiptKey(grantID string, seq int) []byte {
	return store.Key(store.PrefixEnroll, "receipt", grantID, fmt.Sprintf("%06d", seq))
}

func localKey(grantID, enrollee string) []byte {
	if enrollee == "" {
		enrollee = "_"
	}
	return store.Key(store.PrefixEnroll, "local", grantID, enrollee)
}

func grantMetaKey(grantID string) []byte {
	return store.Key(store.PrefixEnroll, "grant", grantID, "meta")
}

func (m Manifest) Grant() string {
	if m.GrantID != "" {
		return m.GrantID
	}
	return m.EnrollmentID
}

func (m Manifest) allowed() AllowedUses {
	if m.Scope.AllowedUses.Mode != "" {
		return m.Scope.AllowedUses
	}
	if m.Scope.MaxUses > 0 {
		if m.Scope.MaxUses == 1 {
			return AllowedUses{Mode: UseExactlyOne, Count: 1}
		}
		return AllowedUses{Mode: UseFinite, Count: m.Scope.MaxUses}
	}
	return AllowedUses{Mode: UseExactlyOne, Count: 1}
}

// RegisterGrant records a grant on the issuer ledger at zero uses. Idempotent.
func RegisterGrant(st store.Store, m Manifest) error {
	if _, err := Verify(m); err != nil {
		return err
	}
	uses, err := m.allowed().Normalize()
	if err != nil {
		return err
	}
	meta := map[string]any{
		"grantID":     m.Grant(),
		"manifestID":  m.ManifestID,
		"issuer":      m.IssuerNodeID,
		"orgID":       m.Scope.OrgID,
		"allowedUses": uses,
		"expiresAt":   m.ExpiresAt,
	}
	if err := store.PutJSON(st, grantMetaKey(m.Grant()), meta); err != nil {
		return err
	}
	zero, err := json.Marshal(grantCounter{GrantID: m.Grant(), Uses: 0})
	if err != nil {
		return err
	}
	err = st.CompareAndSwap(counterKey(m.Grant()), nil, zero)
	if err == nil || errors.Is(err, store.ErrCASConflict) {
		return nil
	}
	return err
}

func LocallyEnrolled(st store.Store, grantID, enrolleeNodeID string) (UseReceipt, bool, error) {
	var rec UseReceipt
	ok, err := store.GetJSON(st, localKey(grantID, enrolleeNodeID), &rec)
	return rec, ok, err
}

func ListReceipts(st store.Store, grantID string) ([]UseReceipt, error) {
	var out []UseReceipt
	prefix := store.Key(store.PrefixEnroll, "receipt", grantID)
	err := st.PrefixScan(prefix, func(key, value []byte) error {
		var r UseReceipt
		if err := json.Unmarshal(value, &r); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func useCount(st store.Store, grantID string) (int, error) {
	var c grantCounter
	ok, err := store.GetJSON(st, counterKey(grantID), &c)
	if err != nil || !ok {
		return 0, err
	}
	return c.Uses, nil
}

func consumeUse(st store.Store, m Manifest, enrolleeNodeID string) (UseReceipt, error) {
	grantID := m.Grant()
	if enrolleeNodeID != "" {
		if existing, ok, err := LocallyEnrolled(st, grantID, enrolleeNodeID); err != nil {
			return UseReceipt{}, err
		} else if ok {
			return existing, nil
		}
	}
	allowed, err := m.allowed().Normalize()
	if err != nil {
		return UseReceipt{}, err
	}
	var rec UseReceipt
	for attempt := 0; attempt < 32; attempt++ {
		raw, ok, err := st.Get(counterKey(grantID))
		if err != nil {
			return UseReceipt{}, err
		}
		used := 0
		if ok {
			var c grantCounter
			if err := json.Unmarshal(raw, &c); err != nil {
				return UseReceipt{}, err
			}
			used = c.Uses
		} else {
			raw = nil
		}
		if err := allowed.Allows(used); err != nil {
			return UseReceipt{}, err
		}
		next := used + 1
		newRaw, err := json.Marshal(grantCounter{GrantID: grantID, Uses: next})
		if err != nil {
			return UseReceipt{}, err
		}
		if err := st.CompareAndSwap(counterKey(grantID), raw, newRaw); err != nil {
			if errors.Is(err, store.ErrCASConflict) {
				continue
			}
			return UseReceipt{}, err
		}
		rec = UseReceipt{
			GrantID:        grantID,
			UseSeq:         next,
			EnrolleeNodeID: enrolleeNodeID,
			At:             time.Now().UTC(),
			Mode:           allowed.Mode,
			AllowedCount:   allowed.Count,
			ManifestID:     m.ManifestID,
			OrgID:          m.Scope.OrgID,
			Summary:        fmt.Sprintf("enrollment use %d of grant %s (%s)", next, grantID, allowed.PolicyLine()),
		}
		if err := store.PutJSON(st, receiptKey(grantID, next), rec); err != nil {
			return UseReceipt{}, err
		}
		if enrolleeNodeID != "" {
			if err := store.PutJSON(st, localKey(grantID, enrolleeNodeID), rec); err != nil {
				return UseReceipt{}, err
			}
		}
		_ = intent.AppendAudit(st, intent.AuditEvent{
			IntentID:     fmt.Sprintf("enroll:%s:%d", grantID, next),
			Kind:         "enrollment.use",
			Status:       intent.Succeeded,
			ActorNodeID:  enrolleeNodeID,
			TargetNodeID: m.IssuerNodeID,
			Summary:      rec.Summary,
		})
		return rec, nil
	}
	return UseReceipt{}, fmt.Errorf("grant consume lost the race too many times")
}

// RecordLedgerUse applies a per-use receipt to an issuer ledger atomically.
// Duplicate enrollee reports are idempotent. Revoked grants are refused.
func RecordLedgerUse(st store.Store, rec UseReceipt, allowed AllowedUses) error {
	if rec.GrantID == "" {
		return fmt.Errorf("grant id required")
	}
	if revoked, err := IsRevoked(st, rec.GrantID); err != nil {
		return err
	} else if revoked {
		return fmt.Errorf("enrollment grant revoked")
	}
	if rec.EnrolleeNodeID != "" {
		if _, ok, err := LocallyEnrolled(st, rec.GrantID, rec.EnrolleeNodeID); err != nil {
			return err
		} else if ok {
			return nil
		}
	}
	allowed, err := allowed.Normalize()
	if err != nil {
		return err
	}
	stub := Manifest{GrantID: rec.GrantID, EnrollmentID: rec.GrantID, Scope: Scope{AllowedUses: allowed}}
	got, err := consumeUse(st, stub, rec.EnrolleeNodeID)
	if err != nil {
		return err
	}
	_ = got
	return nil
}
