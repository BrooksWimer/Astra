package strategy

import (
	"net"
	"strings"
)

type DnsQueryObservation struct{}

func (s *DnsQueryObservation) Name() string {
	return "dns_query_observation"
}

func (s *DnsQueryObservation) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		h := strings.TrimSpace(t.Hostname)
		if h == "" {
			emitObservation(emit, s.Name(), t, "dns_query", "no_hostname", nil)
			continue
		}
		ips, err := net.LookupIP(h)
		if err != nil || len(ips) == 0 {
			emitObservation(emit, s.Name(), t, "dns_query", "lookup_error", nil)
			continue
		}
		for _, ip := range ips {
			emitObservation(emit, s.Name(), t, "dns_query", ip.String(), nil)
		}
	}
}
