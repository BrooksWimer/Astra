package strategy

import (
	"sort"
	"strconv"
)

type PassiveServiceFingerprintPcap struct{}

func (s *PassiveServiceFingerprintPcap) Name() string {
	return "passive_service_fingerprint_pcap"
}

func (s *PassiveServiceFingerprintPcap) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	reason := passiveHostStatusReason(corpus)
	type aggregateKey struct {
		Quality   string
		Transport string
		SrcPort   int
		DstPort   int
		Protocol  string
		Peer      string
		Direction string
	}
	for _, t := range targets {
		if reason != "" {
			emitObservation(emit, s.Name(), t, "passive_flow_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		aggregates := map[aggregateKey]passiveWindowStat{}
		for _, flow := range corpus.Flows {
			quality, direction, peer, ok := passiveMatchFlowTarget(t, flow.SrcIP, flow.DstIP, flow.SrcMAC, flow.DstMAC)
			if !ok {
				continue
			}
			key := aggregateKey{
				Quality:   quality,
				Transport: flow.Transport,
				SrcPort:   flow.SrcPort,
				DstPort:   flow.DstPort,
				Protocol:  flow.Protocol,
				Peer:      peer,
				Direction: direction,
			}
			stat := aggregates[key]
			stat.Add(flow.Timestamp)
			aggregates[key] = stat
		}
		if len(aggregates) == 0 {
			emitObservation(emit, s.Name(), t, "passive_flow_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "no_matched_flows", nil))
			continue
		}
		keys := make([]aggregateKey, 0, len(aggregates))
		for key := range aggregates {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].Protocol != keys[j].Protocol {
				return keys[i].Protocol < keys[j].Protocol
			}
			if keys[i].Peer != keys[j].Peer {
				return keys[i].Peer < keys[j].Peer
			}
			if keys[i].DstPort != keys[j].DstPort {
				return keys[i].DstPort < keys[j].DstPort
			}
			return keys[i].SrcPort < keys[j].SrcPort
		})
		emitObservation(emit, s.Name(), t, "passive_flow_status", "observed", passiveObservationDetails(corpus, keys[0].Quality, "host_passive", aggregates[keys[0]], map[string]string{"groups": strconv.Itoa(len(keys))}))
		for _, key := range keys {
			details := passiveObservationDetails(corpus, key.Quality, "host_passive", aggregates[key], nil)
			emitObservation(emit, s.Name(), t, "passive_flow_transport", key.Transport, details)
			emitObservation(emit, s.Name(), t, "passive_flow_src_port", strconv.Itoa(key.SrcPort), details)
			emitObservation(emit, s.Name(), t, "passive_flow_dst_port", strconv.Itoa(key.DstPort), details)
			emitObservation(emit, s.Name(), t, "passive_flow_protocol", key.Protocol, details)
			emitObservation(emit, s.Name(), t, "passive_flow_peer", key.Peer, details)
			emitObservation(emit, s.Name(), t, "passive_flow_direction", key.Direction, details)
			emitObservation(emit, s.Name(), t, "passive_flow_count", strconv.Itoa(aggregates[key].Count), details)
		}
	}
}
