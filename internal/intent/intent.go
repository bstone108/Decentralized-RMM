package intent

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/store"
)

type Status string

const (
	Queued       Status = "queued"
	Routed       Status = "routed"
	Received     Status = "received"
	Validated    Status = "validated"
	Applying     Status = "applying"
	Succeeded    Status = "succeeded"
	Failed       Status = "failed"
	Acknowledged Status = "acknowledged"
)

type Kind string

const (
	KindInventoryCollect  Kind = "inventory.collect"
	KindConfigApply       Kind = "config.apply"
	KindAppInstall        Kind = "app.install"
	KindAppUpdate         Kind = "app.update"
	KindAppRemove         Kind = "app.remove"
	KindAppVerify         Kind = "app.verify"
	KindServiceControl    Kind = "service.control"
	KindCommandRun        Kind = "command.run"
	KindDesktopSession    Kind = "desktop.session.request"
	KindDesktopModeChange Kind = "desktop.mode.change"
)

type Intent struct {
	ID             string          `json:"id"`
	IdempotencyKey string          `json:"idempotencyKey"`
	OriginNodeID   string          `json:"originNodeID"`
	TargetNodeID   string          `json:"targetNodeID"`
	Kind           Kind            `json:"kind"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
	Status         Status          `json:"status"`
	LastError      string          `json:"lastError,omitempty"`
}

type Receipt struct {
	IntentID     string          `json:"intentID"`
	Status       Status          `json:"status"`
	OriginNodeID string          `json:"originNodeID"`
	TargetNodeID string          `json:"targetNodeID"`
	Kind         Kind            `json:"kind"`
	UpdatedAt    time.Time       `json:"updatedAt"`
	LastError    string          `json:"lastError,omitempty"`
	Summary      string          `json:"summary,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
}

func (s Status) TerminalTarget() bool {
	return s == Succeeded || s == Failed
}

func CanTransition(from, to Status) bool {
	if from == to {
		return true
	}
	allowed := map[Status][]Status{
		Queued:       {Routed},
		Routed:       {Received},
		Received:     {Validated, Failed},
		Validated:    {Applying, Failed},
		Applying:     {Succeeded, Failed},
		Succeeded:    {Acknowledged},
		Failed:       {Acknowledged},
		Acknowledged: {},
	}
	for _, next := range allowed[from] {
		if next == to {
			return true
		}
	}
	return false
}

func (in *Intent) Transition(to Status, lastError string) error {
	if !CanTransition(in.Status, to) {
		return fmt.Errorf("illegal intent transition %s → %s", in.Status, to)
	}
	if to == Failed && lastError == "" {
		return fmt.Errorf("failed pending intent requires last error")
	}
	in.Status = to
	in.UpdatedAt = time.Now().UTC()
	if lastError != "" {
		in.LastError = lastError
	}
	return nil
}

func ValidateSchema(in Intent) error {
	if in.ID == "" || in.IdempotencyKey == "" {
		return fmt.Errorf("intent id and idempotency key are required")
	}
	if in.OriginNodeID == "" || in.TargetNodeID == "" {
		return fmt.Errorf("origin and target node ids are required")
	}
	switch in.Kind {
	case KindInventoryCollect, KindConfigApply, KindAppInstall, KindAppUpdate,
		KindAppRemove, KindAppVerify, KindServiceControl, KindCommandRun,
		KindDesktopSession, KindDesktopModeChange:
		return nil
	default:
		return fmt.Errorf("unknown intent kind %q", in.Kind)
	}
}

func IntentKey(id string) []byte {
	return store.Key(store.PrefixIntent, id)
}

func IdemKey(key string) []byte {
	return store.Key(store.PrefixIdem, key)
}

func ReceiptKey(id string) []byte {
	return store.Key(store.PrefixReceipt, id)
}

func Save(st store.Store, in Intent) error {
	if err := store.PutJSON(st, IntentKey(in.ID), in); err != nil {
		return err
	}
	return st.Put(IdemKey(in.IdempotencyKey), []byte(in.ID))
}

func Load(st store.Store, id string) (Intent, bool, error) {
	var in Intent
	ok, err := store.GetJSON(st, IntentKey(id), &in)
	return in, ok, err
}

func LoadByIdempotency(st store.Store, key string) (Intent, bool, error) {
	id, ok, err := st.Get(IdemKey(key))
	if err != nil || !ok {
		return Intent{}, ok, err
	}
	return Load(st, string(id))
}

func SaveReceipt(st store.Store, r Receipt) error {
	return store.PutJSON(st, ReceiptKey(r.IntentID), r)
}

func LoadReceipt(st store.Store, id string) (Receipt, bool, error) {
	var r Receipt
	ok, err := store.GetJSON(st, ReceiptKey(id), &r)
	return r, ok, err
}

func New(id, idem, origin, target string, kind Kind, payload []byte) Intent {
	now := time.Now().UTC()
	return Intent{
		ID:             id,
		IdempotencyKey: idem,
		OriginNodeID:   origin,
		TargetNodeID:   target,
		Kind:           kind,
		Payload:        append(json.RawMessage(nil), payload...),
		CreatedAt:      now,
		UpdatedAt:      now,
		Status:         Queued,
	}
}

func (in Intent) Receipt(summary string, result []byte) Receipt {
	return Receipt{
		IntentID:     in.ID,
		Status:       in.Status,
		OriginNodeID: in.OriginNodeID,
		TargetNodeID: in.TargetNodeID,
		Kind:         in.Kind,
		UpdatedAt:    in.UpdatedAt,
		LastError:    in.LastError,
		Summary:      summary,
		Result:       result,
	}
}
