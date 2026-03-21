package strategy

type PassiveTLSClientFingerprint struct{}

func (s *PassiveTLSClientFingerprint) Name() string {
	return "passive_tls_client_fingerprint"
}

func (s *PassiveTLSClientFingerprint) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.TLSClients) == 0 {
			reason := passiveHostStatusReason(corpus)
			if reason == "" {
				reason = "no_tls_client_fingerprint_data"
			}
			emitObservation(emit, s.Name(), t, "tls_client_fingerprint_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.TLSClients {
			quality, ok := passiveMatchIdentity(t, ev.SrcIP, ev.SrcMAC, "")
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "host_passive", stat, nil)
			if ev.JA3 != "" {
				emitObservation(emit, s.Name(), t, "tls_client_ja3", ev.JA3, details)
				emitted = true
			}
			if ev.Version != "" {
				emitObservation(emit, s.Name(), t, "tls_client_version", ev.Version, details)
				emitted = true
			}
			if ev.ALPN != "" {
				emitObservation(emit, s.Name(), t, "tls_client_alpn", ev.ALPN, details)
				emitted = true
			}
			if ev.SNICategory != "" {
				emitObservation(emit, s.Name(), t, "tls_client_sni_category", ev.SNICategory, details)
				emitted = true
			}
			if ev.CipherOrderHash != "" {
				emitObservation(emit, s.Name(), t, "tls_client_cipher_order_hash", ev.CipherOrderHash, details)
				emitted = true
			}
			if ev.ExtensionOrderHash != "" {
				emitObservation(emit, s.Name(), t, "tls_client_extension_order_hash", ev.ExtensionOrderHash, details)
				emitted = true
			}
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "tls_client_fingerprint_status", "observed", passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "tls_client_fingerprint_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "target_not_seen_in_tls_client", nil))
	}
}
