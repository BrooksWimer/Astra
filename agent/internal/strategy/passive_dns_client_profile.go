package strategy

import "strconv"

type PassiveDNSClientProfile struct{}

func (s *PassiveDNSClientProfile) Name() string {
	return "passive_dns_client_profile"
}

func (s *PassiveDNSClientProfile) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.DNS) == 0 {
			reason := passiveHostStatusReason(corpus)
			if reason == "" {
				reason = "no_dns_profile_data"
			}
			emitObservation(emit, s.Name(), t, "dns_client_profile_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		total := 0
		reverse := 0
		local := 0
		unique := map[string]struct{}{}
		categories := map[string]int{}
		transports := map[string]int{}
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.DNS {
			quality, ok := passiveMatchIdentity(t, ev.ClientIP, ev.ClientMAC, "")
			if !ok {
				continue
			}
			total++
			unique[ev.Query] = struct{}{}
			categories[ev.Category]++
			transports[ev.Transport]++
			if ev.IsReverse {
				reverse++
			}
			if ev.IsLocal {
				local++
			}
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if total == 0 {
			emitObservation(emit, s.Name(), t, "dns_client_profile_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "target_not_seen_in_dns", nil))
			continue
		}
		details := passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil)
		emitObservation(emit, s.Name(), t, "dns_query_count", strconv.Itoa(total), details)
		emitObservation(emit, s.Name(), t, "dns_unique_query_count", strconv.Itoa(len(unique)), details)
		emitObservation(emit, s.Name(), t, "dns_reverse_lookup_count", strconv.Itoa(reverse), details)
		emitObservation(emit, s.Name(), t, "dns_local_lookup_count", strconv.Itoa(local), details)
		for category, count := range categories {
			emitObservation(emit, s.Name(), t, "dns_query_category", category, passiveObservationDetails(corpus, bestQuality, "host_passive", best, map[string]string{"count": strconv.Itoa(count)}))
		}
		for transport, count := range transports {
			emitObservation(emit, s.Name(), t, "dns_query_transport", transport, passiveObservationDetails(corpus, bestQuality, "host_passive", best, map[string]string{"count": strconv.Itoa(count)}))
		}
		emitObservation(emit, s.Name(), t, "dns_client_profile_status", "observed", details)
	}
}
