package strategy

import "net"
import "strings"

type ManualOperatorLabelFallback struct{}

func (s *ManualOperatorLabelFallback) Name() string {
	return "manual_operator_label_fallback"
}

func (s *ManualOperatorLabelFallback) Collect(targets []Target, emit ObservationSink) {
	labels := manualOperatorLabels()
	for _, t := range targets {
		matched, selector, matchType := manualOperatorMatch(t, labels)
		if matched != "" {
			emitObservation(emit, s.Name(), t, "manual_label", matched, map[string]string{
				"selector":   selector,
				"match_type": matchType,
				"provenance": "operator_override",
				"precedence": "high",
			})
			continue
		}
		emitObservation(emit, s.Name(), t, "manual_label", "unlabeled", map[string]string{
			"reason":     "no_override",
			"provenance": "operator_override",
			"precedence": "none",
		})
	}
}

func manualOperatorMatch(t Target, labels map[string]string) (label, selector, matchType string) {
	if t.IP == "" && t.Hostname == "" && t.MAC == "" {
		return "", "", ""
	}
	ip := strings.TrimSpace(t.IP)
	host := strings.ToLower(strings.TrimSpace(t.Hostname))
	mac := normalizeMAC(t.MAC)
	bestRank := 0
	for selectorKey, labelValue := range labels {
		candidateSelector := strings.ToLower(strings.TrimSpace(selectorKey))
		rank := 0
		switch {
		case ip != "" && candidateSelector == strings.ToLower(ip):
			rank = 4
		case mac != "" && normalizeMAC(candidateSelector) == mac:
			rank = 4
		case host != "" && candidateSelector == host:
			rank = 3
		case host != "" && candidateSelector == strings.TrimSuffix(host, ".local"):
			rank = 3
		case ip != "" && selectorIsCIDR(candidateSelector) && cidrContains(candidateSelector, ip):
			rank = 2
		}
		if rank <= bestRank {
			continue
		}
		bestRank = rank
		label = labelValue
		selector = selectorKey
		switch rank {
		case 4:
			matchType = "exact"
		case 3:
			matchType = "hostname"
		case 2:
			matchType = "cidr"
		}
	}
	return label, selector, matchType
}

func selectorIsCIDR(v string) bool {
	_, _, err := net.ParseCIDR(v)
	return err == nil
}

func cidrContains(cidr, ip string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return network.Contains(parsed)
}

func normalizeMAC(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", "")
	v = strings.ReplaceAll(v, ":", "")
	v = strings.ReplaceAll(v, ".", "")
	v = strings.ReplaceAll(v, " ", "")
	return v
}
