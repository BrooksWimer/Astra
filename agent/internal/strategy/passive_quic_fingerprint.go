package strategy

type PassiveQUICFingerprint struct{}

func (s *PassiveQUICFingerprint) Name() string {
	return "passive_quic_fingerprint"
}

func (s *PassiveQUICFingerprint) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.QUIC) == 0 {
			reason := passiveHostStatusReason(corpus)
			if reason == "" {
				reason = "no_quic_fingerprint_data"
			}
			emitObservation(emit, s.Name(), t, "quic_client_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.QUIC {
			quality, ok := passiveMatchIdentity(t, ev.SrcIP, ev.SrcMAC, "")
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "host_passive", stat, nil)
			if ev.Version != "" {
				emitObservation(emit, s.Name(), t, "quic_version", ev.Version, details)
				emitted = true
			}
			if ev.SNICategory != "" {
				emitObservation(emit, s.Name(), t, "quic_sni_category", ev.SNICategory, details)
				emitted = true
			}
			if ev.ALPN != "" {
				emitObservation(emit, s.Name(), t, "quic_alpn", ev.ALPN, details)
				emitted = true
			}
			if ev.FingerprintHash != "" {
				emitObservation(emit, s.Name(), t, "quic_fingerprint_hash", ev.FingerprintHash, details)
				emitted = true
			}
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "quic_client_status", "observed", passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "quic_client_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "target_not_seen_in_quic", nil))
	}
}
