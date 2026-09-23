package intent

import (
	"encoding/json"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/security"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

type AuditEvent struct {
	At           time.Time `json:"at"`
	IntentID     string    `json:"intentID"`
	Kind         Kind      `json:"kind"`
	Status       Status    `json:"status"`
	ActorNodeID  string    `json:"actorNodeID"`
	TargetNodeID string    `json:"targetNodeID,omitempty"`
	Summary      string    `json:"summary,omitempty"`
	LastError    string    `json:"lastError,omitempty"`
}

func AppendAudit(st store.Store, e AuditEvent) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	e.Summary = security.RedactString(e.Summary)
	e.LastError = security.RedactString(e.LastError)
	key := store.Key(store.PrefixAudit, e.At.UTC().Format("20060102T150405.000000000Z"), e.IntentID)
	return store.PutJSON(st, key, e)
}

func ListAudit(st store.Store) ([]AuditEvent, error) {
	var out []AuditEvent
	err := st.PrefixScan([]byte(store.PrefixAudit), func(key, value []byte) error {
		var e AuditEvent
		if err := json.Unmarshal(value, &e); err != nil {
			return err
		}
		out = append(out, e)
		return nil
	})
	return out, err
}
