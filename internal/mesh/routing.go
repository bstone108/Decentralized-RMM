package mesh

import "sort"

type PathKind string

const (
	PathDirectLocal PathKind = "direct_local"
	PathDirectWAN   PathKind = "direct_wan"
	PathVPN         PathKind = "vpn_overlay"
	PathRelay       PathKind = "relay"
	PathTunnel      PathKind = "tunnel"
)

type Candidate struct {
	NodeID    string
	Address   string
	Kind      PathKind
	Reachable bool
	Trusted   bool
}

type Route struct {
	Candidate
	RelayedMayBeSlow bool
	Reason           string
}

// PlanManagementPath prefers direct routes. Relays/tunnels are allowed for
// management only when the candidate is already trusted. Discovery is not trust.
func PlanManagementPath(candidates []Candidate) (Route, bool) {
	usable := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if !c.Reachable || !c.Trusted {
			continue
		}
		usable = append(usable, c)
	}
	if len(usable) == 0 {
		return Route{}, false
	}
	rank := map[PathKind]int{
		PathDirectLocal: 0,
		PathDirectWAN:   1,
		PathVPN:         2,
		PathRelay:       3,
		PathTunnel:      4,
	}
	sort.SliceStable(usable, func(i, j int) bool {
		return rank[usable[i].Kind] < rank[usable[j].Kind]
	})
	c := usable[0]
	r := Route{Candidate: c, Reason: "direct encrypted management path"}
	if c.Kind == PathRelay || c.Kind == PathTunnel {
		r.RelayedMayBeSlow = true
		r.Reason = "trusted relay/tunnel management path may be slow"
	}
	return r, true
}

type DiscoverySource string

const (
	SourceLocal      DiscoverySource = "local"
	SourceDHT        DiscoverySource = "dht"
	SourceExchange   DiscoverySource = "peer_exchange"
	SourceConfigured DiscoverySource = "configured"
	SourceRelay      DiscoverySource = "relay"
	SourceTunnel     DiscoverySource = "tunnel"
)

// Discovered is never implicitly trusted.
type Discovered struct {
	NodeID  string
	Address string
	Source  DiscoverySource
	Trusted bool
}

func AllowConnect(d Discovered) error {
	if !d.Trusted {
		return errUntrustedDiscovery
	}
	return nil
}

var errUntrustedDiscovery = errDiscovery{}

type errDiscovery struct{}

func (errDiscovery) Error() string {
	return "discovery grants nothing; cryptographic trust is required before connect or relay offer"
}
