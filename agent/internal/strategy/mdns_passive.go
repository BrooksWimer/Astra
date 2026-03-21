package strategy

import "strconv"

type MdnsPassive struct{}

func (s *MdnsPassive) Name() string {
	return "mdns_passive"
}

func (s *MdnsPassive) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	reason := passiveHostStatusReason(corpus)
	for _, t := range targets {
		if reason != "" {
			emitObservation(emit, s.Name(), t, "mdns_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.MDNS {
			quality, ok := passiveMatchIdentity(t, ev.SrcIP, ev.SrcMAC, ev.Hostname)
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "host_passive", stat, map[string]string{"interface": corpus.Interface})
			switch ev.MessageType {
			case "query":
				emitObservation(emit, s.Name(), t, "mdns_query_name", ev.Name, details)
				emitObservation(emit, s.Name(), t, "mdns_query_type", ev.QueryType, details)
				emitObservation(emit, s.Name(), t, "mdns_query_service_family", ev.ServiceFamily, details)
			default:
				emitObservation(emit, s.Name(), t, "mdns_service", ev.Name, details)
				if ev.Instance != "" {
					emitObservation(emit, s.Name(), t, "mdns_instance", ev.Instance, details)
				}
				if ev.Hostname != "" {
					emitObservation(emit, s.Name(), t, "mdns_hostname", ev.Hostname, details)
				}
				emitObservation(emit, s.Name(), t, "mdns_ttl", strconv.FormatUint(uint64(ev.TTL), 10), details)
				emitObservation(emit, s.Name(), t, "mdns_interface", corpus.Interface, details)
			}
			emitted = true
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "mdns_status", "observed", passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "mdns_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "no_mdns_passive_hits", nil))
	}
}
