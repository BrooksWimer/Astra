package strategy

import (
	"net"
	"strings"
)

type DnsReversePtr struct{}

func (s *DnsReversePtr) Name() string {
	return "dns_ptr_reverse"
}

func (s *DnsReversePtr) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		names, err := net.LookupAddr(t.IP)
		if err != nil || len(names) == 0 {
			emitObservation(emit, s.Name(), t, "ptr", "none", nil)
			continue
		}
		for _, n := range names {
			emitObservation(emit, s.Name(), t, "ptr", strings.TrimSuffix(n, "."), nil)
		}
	}
}
