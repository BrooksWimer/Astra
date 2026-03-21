package strategy

import (
	"sort"
	"strconv"
	"strings"
)

type TcpConnectPortMicroset struct{}

func (s *TcpConnectPortMicroset) Name() string {
	return "tcp_connect_microset"
}

func (s *TcpConnectPortMicroset) Collect(targets []Target, emit ObservationSink) {
	openPorts := []int{22, 80, 443, 445, 554, 631, 3389, 5353, 1900, 8080, 8443, 9100}
	for _, t := range targets {
		found := []string{}
		for _, p := range openPorts {
			if isTCPPortOpen(t.IP, p, strategyProbeTimeout) {
				found = append(found, strconv.Itoa(p))
			}
		}
		if len(found) == 0 {
			emitObservation(emit, s.Name(), t, "ports", "none", nil)
			continue
		}
		sort.Strings(found)
		emitObservation(emit, s.Name(), t, "ports", strings.Join(found, ","), nil)
	}
}
