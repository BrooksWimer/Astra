package strategy

import "strconv"

type PassiveSessionProfile struct{}

func (s *PassiveSessionProfile) Name() string {
	return "passive_session_profile"
}

func (s *PassiveSessionProfile) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.Sessions) == 0 {
			reason := "no_session_profile_source"
			if !corpus.InfraEnabled {
				reason = "passive_infra_disabled"
			}
			emitObservation(emit, s.Name(), t, "session_profile_status", "unavailable", passiveStatusDetails(corpus, "infra_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.Sessions {
			quality, ok := passiveMatchIdentity(t, ev.ClientIP, ev.ClientMAC, "")
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "infra_passive", stat, nil)
			emitObservation(emit, s.Name(), t, "session_count", strconv.Itoa(ev.SessionCount), details)
			if ev.ProtocolMix != "" {
				emitObservation(emit, s.Name(), t, "session_protocol_mix", ev.ProtocolMix, details)
			}
			emitObservation(emit, s.Name(), t, "session_long_lived_count", strconv.Itoa(ev.LongLivedCount), details)
			if ev.RemoteCategory != "" {
				emitObservation(emit, s.Name(), t, "session_remote_category", ev.RemoteCategory, details)
			}
			if ev.Burstiness != "" {
				emitObservation(emit, s.Name(), t, "session_burstiness", ev.Burstiness, details)
			}
			emitted = true
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "session_profile_status", "observed", passiveObservationDetails(corpus, bestQuality, "infra_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "session_profile_status", "not_seen", passiveStatusDetails(corpus, "infra_passive", "target_not_seen_in_sessions", nil))
	}
}
