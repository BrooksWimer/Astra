package strategy

import (
	"strconv"
	"strings"
)

type FlowNetflowIpfix struct{}

func (s *FlowNetflowIpfix) Name() string { return "flow_netflow_ipfix" }

func (s *FlowNetflowIpfix) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.Netflow) == 0 {
			reason := "no_netflow_observed"
			if !corpus.HostCaptureEnabled && !corpus.InfraEnabled {
				reason = "passive_capture_disabled"
			}
			emitObservation(emit, s.Name(), t, "flow_status", "unavailable", passiveStatusDetails(corpus, "passive_flow_collector", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.Netflow {
			quality := ""
			if strings.EqualFold(strings.TrimSpace(ev.ExporterIP), strings.TrimSpace(t.IP)) {
				quality = "direct_match"
			} else if strings.EqualFold(strings.TrimSpace(ev.SrcIP), strings.TrimSpace(t.IP)) || strings.EqualFold(strings.TrimSpace(ev.DstIP), strings.TrimSpace(t.IP)) {
				quality = "strong_inferred_match"
			}
			if quality == "" {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "passive_flow_collector", stat, nil)
			if ev.ExporterIP != "" {
				emitObservation(emit, s.Name(), t, "flow_exporter", ev.ExporterIP, details)
			}
			if ev.ObservationDomain != "" {
				emitObservation(emit, s.Name(), t, "flow_observation_domain", ev.ObservationDomain, details)
			}
			if ev.TemplateID != "" {
				emitObservation(emit, s.Name(), t, "flow_template_id", ev.TemplateID, details)
			}
			if ev.PEN != "" {
				emitObservation(emit, s.Name(), t, "flow_pen", ev.PEN, details)
			}
			if ev.Protocol != "" {
				emitObservation(emit, s.Name(), t, "flow_protocol", ev.Protocol, details)
			}
			emitted = true
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "flow_status", "observed", passiveObservationDetails(corpus, bestQuality, "passive_flow_collector", best, map[string]string{"records": strconv.Itoa(best.Count)}))
			continue
		}
		emitObservation(emit, s.Name(), t, "flow_status", "not_seen", passiveStatusDetails(corpus, "passive_flow_collector", "target_not_seen_in_flow_export", nil))
	}
}
