package strategy

import "strings"

type PassiveDHCPFingerprint struct{}

func (s *PassiveDHCPFingerprint) Name() string {
	return "passive_dhcp_fingerprint"
}

func (s *PassiveDHCPFingerprint) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.DHCP) == 0 {
			reason := passiveHostStatusReason(corpus)
			if reason == "" {
				reason = "no_dhcp_fingerprint_data"
			}
			emitObservation(emit, s.Name(), t, "dhcp_fingerprint_status", "unavailable", passiveStatusDetails(corpus, "host_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.DHCP {
			quality, ok := passiveMatchIdentity(t, firstNonEmpty(ev.ClientIP, ev.RequestedIP), ev.ClientMAC, ev.Hostname)
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "host_passive", stat, nil)
			if len(ev.PRL) > 0 {
				emitObservation(emit, s.Name(), t, "dhcp_prl", strings.Join(ev.PRL, ","), details)
				emitted = true
			}
			if len(ev.OptionOrder) > 0 {
				emitObservation(emit, s.Name(), t, "dhcp_option_order", strings.Join(ev.OptionOrder, ","), details)
				emitted = true
			}
			if ev.VendorClass != "" {
				emitObservation(emit, s.Name(), t, "dhcp_vendor_class", ev.VendorClass, details)
				emitted = true
			}
			if ev.ClientIdentifier != "" {
				emitObservation(emit, s.Name(), t, "dhcp_client_identifier", ev.ClientIdentifier, details)
				emitted = true
			}
			if ev.RequestedIP != "" {
				emitObservation(emit, s.Name(), t, "dhcp_requested_address", ev.RequestedIP, details)
				emitted = true
			}
			if ev.Hostname != "" {
				emitObservation(emit, s.Name(), t, "dhcp_hostname", ev.Hostname, details)
				emitted = true
			}
			if ev.MessageType != "" {
				emitObservation(emit, s.Name(), t, "dhcp_message_type", ev.MessageType, details)
				emitted = true
			}
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "dhcp_fingerprint_status", "observed", passiveObservationDetails(corpus, bestQuality, "host_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "dhcp_fingerprint_status", "not_seen", passiveStatusDetails(corpus, "host_passive", "target_not_seen_in_dhcp", nil))
	}
}
