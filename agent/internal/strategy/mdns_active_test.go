package strategy

import (
	"sync"
	"testing"

	"github.com/netwise/agent/internal/mdns"
)

func TestCollectMDNSOnlyEmitsMatchedEntries(t *testing.T) {
	mdnsOnce = sync.Once{}
	cachedMdns = []mdns.Entry{
		{IP: "192.168.4.239", Hostname: "PS5-902BA7.local", Service: "_spotify-connect._tcp", Instance: "SpZc-902BA7"},
	}
	defer func() {
		mdnsOnce = sync.Once{}
		cachedMdns = nil
	}()

	target := Target{IP: "192.168.4.233"}
	var got []Observation
	collectMDNS("mdns_active", "active_browse", []Target{target}, func(obs Observation) {
		got = append(got, obs)
	})

	if len(got) != 1 {
		t.Fatalf("collectMDNS() emitted %d observations, want 1 not_seen status", len(got))
	}
	if got[0].Key != "mdns_status" || got[0].Value != "not_seen" {
		t.Fatalf("collectMDNS() first observation = %s=%s, want mdns_status=not_seen", got[0].Key, got[0].Value)
	}
}

func TestCollectMDNSMatchesNormalizedHostname(t *testing.T) {
	mdnsOnce = sync.Once{}
	cachedMdns = []mdns.Entry{
		{IP: "192.168.4.21", Hostname: "MacBook-Pro-167.local", Service: "_workstation._tcp", Instance: "MacBook-Pro-167"},
	}
	defer func() {
		mdnsOnce = sync.Once{}
		cachedMdns = nil
	}()

	target := Target{IP: "192.168.4.21", Hostname: "MacBook-Pro-167"}
	var got []Observation
	collectMDNS("mdns_active", "active_browse", []Target{target}, func(obs Observation) {
		got = append(got, obs)
	})

	if len(got) == 0 {
		t.Fatalf("collectMDNS() emitted no observations for hostname match")
	}
	seenObserved := false
	seenService := false
	for _, obs := range got {
		if obs.Key == "mdns_status" && obs.Value == "observed" {
			seenObserved = true
		}
		if obs.Key == "mdns_service" && obs.Value == "_workstation._tcp" {
			seenService = true
		}
	}
	if !seenObserved || !seenService {
		t.Fatalf("collectMDNS() missing expected observed/service observations: %+v", got)
	}
}
