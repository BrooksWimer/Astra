package strategy

import (
	"sort"
	"strconv"
	"strings"
)

type PortServiceCorrelation struct{}

func (s *PortServiceCorrelation) Name() string {
	return "port_service_correlation"
}

func (s *PortServiceCorrelation) Collect(targets []Target, emit ObservationSink) {
	tcpPorts := []int{22, 80, 443, 445, 554, 631, 3389, 8080, 8443, 9100}
	udpCandidates := []int{5353, 1900, 5060}
	for _, t := range targets {
		found := []string{}
		for _, p := range tcpPorts {
			if isTCPPortOpen(t.IP, p, strategyProbeTimeout) {
				found = append(found, strconv.Itoa(p))
			}
		}
		if len(found) == 0 {
			emitObservation(emit, s.Name(), t, "tcp_ports", "none", nil)
		} else {
			sort.Strings(found)
			emitObservation(emit, s.Name(), t, "tcp_ports", strings.Join(found, ","), map[string]string{
				"mode": "tcp_only",
			})
			for _, family := range serviceFamiliesFromPorts(found) {
				emitObservation(emit, s.Name(), t, "service_family", family, map[string]string{
					"source": "tcp_port_set",
				})
			}
		}
		for _, p := range udpCandidates {
			emitObservation(emit, s.Name(), t, "udp_candidate_port", strconv.Itoa(p), map[string]string{
				"state":  "not_tcp_probed",
				"reason": "udp_centric_port",
			})
		}
	}
}

func serviceFamiliesFromPorts(ports []string) []string {
	families := []string{}
	has := func(port string) bool {
		for _, p := range ports {
			if p == port {
				return true
			}
		}
		return false
	}
	if has("631") || has("9100") {
		families = append(families, "printer")
	}
	if has("554") {
		families = append(families, "camera")
	}
	if has("3389") {
		families = append(families, "remote_desktop")
	}
	if has("445") {
		families = append(families, "smb_file_share")
	}
	if has("22") {
		families = append(families, "ssh_admin")
	}
	if has("80") || has("443") || has("8080") || has("8443") {
		families = append(families, "web_management")
	}
	if len(families) == 0 {
		families = append(families, "unknown")
	}
	sort.Strings(families)
	return dedupeStrings(families)
}
