package mesh

import "testing"

func TestDHTAnnounceDoesNotTrust(t *testing.T) {
	tab := NewTable()
	tab.Announce("rmm1:x", "10.0.0.9:7946", SourceDHT)
	tab.OfferRelay("rmm1:relay", "10.0.0.1:9")
	got := tab.Lookup("rmm1:x")
	if len(got) != 1 || got[0].Trusted {
		t.Fatalf("%+v", got)
	}
	if err := AllowConnect(got[0]); err == nil {
		t.Fatal("DHT candidate must not be connectable before pairing")
	}
	trusted := got[0]
	trusted.Trusted = true
	if err := AllowConnect(trusted); err != nil {
		t.Fatal(err)
	}
	for _, r := range tab.Relays() {
		if err := AllowConnect(r); err == nil {
			t.Fatal("relay offer is not trust")
		}
	}
}

func TestLocalDiscoveryUntrusted(t *testing.T) {
	c := LocalCandidates("rmm1:a", "127.0.0.1:1")
	if err := AllowConnect(c[0]); err == nil {
		t.Fatal("local discovery grants nothing")
	}
}
