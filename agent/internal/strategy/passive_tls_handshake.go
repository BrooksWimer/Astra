package strategy

import "sort"

type PassiveTLSHandshake struct{}

func (s *PassiveTLSHandshake) Name() string {
	return "passive_tls_handshake"
}

func (s *PassiveTLSHandshake) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	reason := passiveHostStatusReason(corpus)
	type aggregateKey struct {
		Quality string
		Version string
		ALPN    string
		SNI     string
		Cipher  string
		Subject string
		Issuer  string
	}
	for _, t := range targets {
		if reason != "" {
			emitObservation(emit, s.Name(), t, "passive_tls_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		aggregates := map[aggregateKey]passiveWindowStat{}
		for _, ev := range corpus.TLSServers {
			quality, ok := passiveMatchIdentity(t, ev.SrcIP, ev.SrcMAC, "")
			if !ok {
				continue
			}
			key := aggregateKey{
				Quality: quality,
				Version: ev.Version,
				ALPN:    ev.ALPN,
				SNI:     ev.SNI,
				Cipher:  ev.Cipher,
				Subject: ev.CertSubject,
				Issuer:  ev.CertIssuer,
			}
			stat := aggregates[key]
			stat.Add(ev.Timestamp)
			aggregates[key] = stat
		}
		if len(aggregates) == 0 {
			emitObservation(emit, s.Name(), t, "passive_tls_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "no_tls_server_handshake", nil))
			continue
		}
		keys := make([]aggregateKey, 0, len(aggregates))
		for key := range aggregates {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].Version != keys[j].Version {
				return keys[i].Version < keys[j].Version
			}
			return keys[i].Subject < keys[j].Subject
		})
		emitObservation(emit, s.Name(), t, "passive_tls_status", "observed", passiveObservationDetails(corpus, keys[0].Quality, "host_passive", aggregates[keys[0]], nil))
		for _, key := range keys {
			details := passiveObservationDetails(corpus, key.Quality, "host_passive", aggregates[key], nil)
			if key.Version != "" {
				emitObservation(emit, s.Name(), t, "passive_tls_version", key.Version, details)
			}
			if key.ALPN != "" {
				emitObservation(emit, s.Name(), t, "passive_tls_alpn", key.ALPN, details)
			}
			if key.SNI != "" {
				emitObservation(emit, s.Name(), t, "passive_tls_sni", key.SNI, details)
			}
			if key.Cipher != "" {
				emitObservation(emit, s.Name(), t, "passive_tls_cipher", key.Cipher, details)
			}
			if key.Subject != "" {
				emitObservation(emit, s.Name(), t, "passive_tls_cert_subject", key.Subject, details)
			}
			if key.Issuer != "" {
				emitObservation(emit, s.Name(), t, "passive_tls_cert_issuer", key.Issuer, details)
			}
		}
	}
}
