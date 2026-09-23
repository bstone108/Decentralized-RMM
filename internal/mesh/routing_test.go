package mesh

import "testing"

func TestPlanPrefersDirectAndRequiresTrust(t *testing.T) {
	_, ok := PlanManagementPath([]Candidate{
		{NodeID: "a", Address: "relay:1", Kind: PathRelay, Reachable: true, Trusted: false},
	})
	if ok {
		t.Fatal("untrusted relay must not be selected")
	}
	r, ok := PlanManagementPath([]Candidate{
		{NodeID: "a", Address: "1.2.3.4:9", Kind: PathDirectWAN, Reachable: true, Trusted: true},
		{NodeID: "a", Address: "10.0.0.2:9", Kind: PathDirectLocal, Reachable: true, Trusted: true},
		{NodeID: "a", Address: "relay:1", Kind: PathRelay, Reachable: true, Trusted: true},
	})
	if !ok || r.Kind != PathDirectLocal || r.RelayedMayBeSlow {
		t.Fatalf("%+v", r)
	}
}

func TestDiscoveryGrantsNothing(t *testing.T) {
	if err := AllowConnect(Discovered{NodeID: "x", Address: "1.1.1.1:1", Source: SourceDHT, Trusted: false}); err == nil {
		t.Fatal("expected deny")
	}
	if err := AllowConnect(Discovered{NodeID: "x", Trusted: true, Source: SourceConfigured}); err != nil {
		t.Fatal(err)
	}
}
