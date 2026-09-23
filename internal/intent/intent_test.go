package intent

import (
	"testing"

	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func TestLifecycleAndIdempotency(t *testing.T) {
	in := New("id1", "idem-1", "rmm1:a", "rmm1:b", KindInventoryCollect, nil)
	for _, step := range []Status{Routed, Received, Validated, Applying, Succeeded, Acknowledged} {
		if err := in.Transition(step, ""); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	if CanTransition(Succeeded, Applying) {
		t.Fatal("must not re-enter applying")
	}
	st := store.NewMemory()
	in.Status = Queued
	if err := Save(st, in); err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadByIdempotency(st, "idem-1")
	if err != nil || !ok || got.ID != "id1" {
		t.Fatalf("idempotent load %+v ok=%v err=%v", got, ok, err)
	}
	if err := ValidateSchema(New("x", "y", "a", "b", Kind("nope"), nil)); err == nil {
		t.Fatal("unknown kind")
	}
}
