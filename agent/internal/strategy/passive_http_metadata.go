package strategy

import "strconv"

type PassiveHttpMetadata struct{}

func (s *PassiveHttpMetadata) Name() string {
	return "passive_http_metadata"
}

func (s *PassiveHttpMetadata) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	reason := passiveHostStatusReason(corpus)
	for _, t := range targets {
		if reason != "" {
			emitObservation(emit, s.Name(), t, "passive_http_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.HTTP {
			quality, ok := passiveMatchIdentity(t, ev.SrcIP, ev.SrcMAC, "")
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "host_passive", stat, map[string]string{"role": ev.Role})
			if ev.Host != "" {
				emitObservation(emit, s.Name(), t, "passive_http_host", ev.Host, details)
				emitted = true
			}
			if ev.UserAgent != "" {
				emitObservation(emit, s.Name(), t, "passive_http_user_agent", ev.UserAgent, details)
				emitted = true
			}
			if ev.Server != "" {
				emitObservation(emit, s.Name(), t, "passive_http_server", ev.Server, details)
				emitted = true
			}
			if ev.PathHint != "" {
				emitObservation(emit, s.Name(), t, "passive_http_path_hint", ev.PathHint, details)
				emitted = true
			}
			if ev.StatusCode > 0 {
				emitObservation(emit, s.Name(), t, "passive_http_status_code", strconv.Itoa(ev.StatusCode), details)
				emitted = true
			}
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "passive_http_status", "observed", passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "passive_http_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "no_http_metadata", nil))
	}
}
