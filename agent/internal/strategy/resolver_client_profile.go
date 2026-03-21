package strategy

import "strconv"

type ResolverClientProfile struct{}

func (s *ResolverClientProfile) Name() string {
	return "resolver_client_profile"
}

func (s *ResolverClientProfile) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.Resolver) == 0 {
			reason := "no_resolver_profile_source"
			if !corpus.InfraEnabled {
				reason = "passive_infra_disabled"
			}
			emitObservation(emit, s.Name(), t, "resolver_profile_status", "unavailable", passiveStatusDetails(corpus, "infra_passive", reason, nil))
			continue
		}
		total := 0
		localCount := 0
		srvCount := 0
		categories := map[string]int{}
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.Resolver {
			quality, ok := passiveMatchIdentity(t, ev.ClientIP, ev.ClientMAC, "")
			if !ok {
				continue
			}
			total++
			if ev.LocalLookup {
				localCount++
			}
			if ev.SRVLookup {
				srvCount++
			}
			categories[ev.Category]++
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if total == 0 {
			emitObservation(emit, s.Name(), t, "resolver_profile_status", "not_seen", passiveStatusDetails(corpus, "infra_passive", "target_not_seen_in_resolver", nil))
			continue
		}
		details := passiveObservationDetails(corpus, bestQuality, "infra_passive", best, nil)
		emitObservation(emit, s.Name(), t, "resolver_query_count", strconv.Itoa(total), details)
		emitObservation(emit, s.Name(), t, "resolver_srv_lookup_count", strconv.Itoa(srvCount), details)
		emitObservation(emit, s.Name(), t, "resolver_local_lookup_count", strconv.Itoa(localCount), details)
		for category, count := range categories {
			emitObservation(emit, s.Name(), t, "resolver_query_category", category, passiveObservationDetails(corpus, bestQuality, "infra_passive", best, map[string]string{"count": strconv.Itoa(count)}))
		}
		emitObservation(emit, s.Name(), t, "resolver_profile_status", "observed", details)
	}
}
