package strategy

import "strconv"

type IcmpReachability struct{}

func (s *IcmpReachability) Name() string {
	return "icmp_reachability"
}

func (s *IcmpReachability) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		ttl, source := collectTTLViaPing(t.IP)
		if ttl <= 0 {
			emitObservation(emit, s.Name(), t, "icmp_like", "unavailable", map[string]string{
				"source": source,
				"reason": "no_icmp_reply",
			})
			emitObservation(emit, s.Name(), t, "icmp_echo", "unavailable", map[string]string{
				"source": source,
			})
			continue
		}
		emitObservation(emit, s.Name(), t, "icmp_like", "reachable", map[string]string{
			"source":    source,
			"reply_ttl": strconv.Itoa(ttl),
			"os_hint":   estimateOSFromTTL(ttl),
		})
		emitObservation(emit, s.Name(), t, "icmp_echo", "reachable", map[string]string{
			"source":    source,
			"reply_ttl": strconv.Itoa(ttl),
		})
	}
}
