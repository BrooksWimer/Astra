package strategy

type PassiveSshBanner struct{}

func (s *PassiveSshBanner) Name() string {
	return "passive_ssh_banner"
}

func (s *PassiveSshBanner) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	reason := passiveHostStatusReason(corpus)
	for _, t := range targets {
		if reason != "" {
			emitObservation(emit, s.Name(), t, "passive_ssh_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.SSH {
			quality, ok := passiveMatchIdentity(t, ev.SrcIP, ev.SrcMAC, "")
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "host_passive", stat, nil)
			if ev.Banner != "" {
				emitObservation(emit, s.Name(), t, "passive_ssh_banner", ev.Banner, details)
				emitted = true
			}
			if ev.Software != "" {
				emitObservation(emit, s.Name(), t, "passive_ssh_software", ev.Software, details)
				emitted = true
			}
			if ev.Proto != "" {
				emitObservation(emit, s.Name(), t, "passive_ssh_proto", ev.Proto, details)
				emitted = true
			}
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "passive_ssh_status", "observed", passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "passive_ssh_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "no_ssh_banner", nil))
	}
}
