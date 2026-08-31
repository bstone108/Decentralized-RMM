package mesh

import "sync"

// Table is a candidate DHT/routing index. Inserting an address never grants
// trust; AllowConnect still requires Trusted on the discovered record.
type Table struct {
	mu     sync.Mutex
	byNode map[string][]Discovered
	relays []Discovered
}

func NewTable() *Table {
	return &Table{byNode: map[string][]Discovered{}}
}

func (t *Table) Announce(nodeID, addr string, source DiscoverySource) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byNode[nodeID] = append(t.byNode[nodeID], Discovered{
		NodeID: nodeID, Address: addr, Source: source, Trusted: false,
	})
}

func (t *Table) OfferRelay(nodeID, addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.relays = append(t.relays, Discovered{
		NodeID: nodeID, Address: addr, Source: SourceRelay, Trusted: false,
	})
}

func (t *Table) Lookup(nodeID string) []Discovered {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := append([]Discovered(nil), t.byNode[nodeID]...)
	return out
}

func (t *Table) Relays() []Discovered {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Discovered(nil), t.relays...)
}

// LocalCandidates turns same-host and configured addresses into untrusted
// discovery records. Pairing is a separate step.
func LocalCandidates(nodeID, addr string) []Discovered {
	return []Discovered{{
		NodeID: nodeID, Address: addr, Source: SourceLocal, Trusted: false,
	}}
}
