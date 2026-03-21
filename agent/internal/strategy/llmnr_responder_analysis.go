package strategy

import (
	"strconv"
	"strings"
)

type LlmnrResponderAnalysis struct{}

func (s *LlmnrResponderAnalysis) Name() string {
	return "llmnr_responder_analysis"
}

func (s *LlmnrResponderAnalysis) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		llmnrResponderAnalysisCollectTarget(t, emit)
	}
}

func llmnrResponderAnalysisCollectTarget(target Target, emit ObservationSink) {
	name := strings.TrimSpace(target.Hostname)
	if name == "" {
		emitObservation(emit, "llmnr_responder_analysis", target, "llmnr_status", "no_hostname", map[string]string{
			"target_ip": target.IP,
		})
		return
	}
	ips := queryLLMNRByName(name)
	emitObservation(emit, "llmnr_responder_analysis", target, "llmnr_query_name", name, map[string]string{
		"target_ip": target.IP,
	})
	emitObservation(emit, "llmnr_responder_analysis", target, "llmnr_responder_count", strconv.Itoa(len(ips)), map[string]string{
		"target_ip": target.IP,
	})
	if len(ips) == 0 {
		emitObservation(emit, "llmnr_responder_analysis", target, "llmnr_status", "no_response", map[string]string{
			"query_name": name,
			"target_ip":   target.IP,
		})
		return
	}
	for _, ip := range ips {
		emitObservation(emit, "llmnr_responder_analysis", target, "llmnr_responder_ip", ip, map[string]string{
			"query_name": name,
			"target_ip":  target.IP,
		})
	}
	emitObservation(emit, "llmnr_responder_analysis", target, "llmnr_status", "observed", map[string]string{
		"query_name":      name,
		"responder_count": strconv.Itoa(len(ips)),
	})
	if len(ips) > 1 {
		emitObservation(emit, "llmnr_responder_analysis", target, "llmnr_conflict", "multiple_responders", map[string]string{
			"query_name":      name,
			"responder_count": strconv.Itoa(len(ips)),
		})
	}
}
