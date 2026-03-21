package strategy

import (
	"strconv"
	"strings"
)

type PassiveIPv6ClientProfile struct{}

func (s *PassiveIPv6ClientProfile) Name() string {
	return "passive_ipv6_client_profile"
}

func (s *PassiveIPv6ClientProfile) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.IPv6) == 0 {
			reason := passiveHostStatusReason(corpus)
			if reason == "" {
				reason = "no_ipv6_client_profile_data"
			}
			emitObservation(emit, s.Name(), t, "ipv6_client_profile_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		total := 0
		privacyHits := 0
		behaviorCounts := map[string]int{}
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.IPv6 {
			quality, ok := passiveMatchIdentity(t, ev.SrcIP, ev.SrcMAC, "")
			if !ok {
				continue
			}
			total++
			if ev.PrivacyAddress {
				privacyHits++
			}
			if ev.SLAACBehavior != "" {
				behaviorCounts[ev.SLAACBehavior]++
			}
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if total == 0 {
			emitObservation(emit, s.Name(), t, "ipv6_client_profile_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "target_not_seen_in_ipv6", nil))
			continue
		}
		details := passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil)
		emitObservation(emit, s.Name(), t, "ipv6_ndp_role", "observed", details)
		emitObservation(emit, s.Name(), t, "ipv6_privacy_address_rotation", strconv.Itoa(privacyHits), details)
		for behavior, count := range behaviorCounts {
			emitObservation(emit, s.Name(), t, "ipv6_slaac_behavior", behavior, passiveObservationDetails(corpus, bestQuality, "host_passive", best, map[string]string{"count": strconv.Itoa(count)}))
		}
		emitObservation(emit, s.Name(), t, "ipv6_client_profile_status", "observed", details)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
