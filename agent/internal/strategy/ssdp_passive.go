package strategy

type SsdpPassive struct{}

func (s *SsdpPassive) Name() string {
	return "ssdp_passive"
}

func (s *SsdpPassive) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	reason := passiveHostStatusReason(corpus)
	for _, t := range targets {
		if reason != "" {
			emitObservation(emit, s.Name(), t, "ssdp_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.SSDP {
			quality, ok := passiveMatchIdentity(t, ev.SrcIP, ev.SrcMAC, "")
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "host_passive", stat, map[string]string{"interface": corpus.Interface})
			if ev.ST != "" {
				emitObservation(emit, s.Name(), t, "ssdp_st", ev.ST, details)
			}
			if ev.USN != "" {
				emitObservation(emit, s.Name(), t, "ssdp_usn", ev.USN, details)
			}
			if ev.Server != "" {
				emitObservation(emit, s.Name(), t, "ssdp_server", ev.Server, details)
			}
			if ev.Location != "" {
				emitObservation(emit, s.Name(), t, "ssdp_location", ev.Location, details)
			}
			if ev.NT != "" {
				emitObservation(emit, s.Name(), t, "ssdp_nt", ev.NT, details)
			}
			if ev.NTS != "" {
				emitObservation(emit, s.Name(), t, "ssdp_nts", ev.NTS, details)
			}
			if ev.CacheControl != "" {
				emitObservation(emit, s.Name(), t, "ssdp_cache_control", ev.CacheControl, details)
			}
			emitObservation(emit, s.Name(), t, "ssdp_source_ip", ev.SrcIP, details)
			emitObservation(emit, s.Name(), t, "ssdp_interface", corpus.Interface, details)
			emitted = true
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "ssdp_status", "observed", passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "ssdp_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "no_ssdp_passive_hits", nil))
	}
}
