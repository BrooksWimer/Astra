package strategy

type WiFiClientAssociationTelemetry struct{}

func (s *WiFiClientAssociationTelemetry) Name() string {
	return "wifi_client_association_telemetry"
}

func (s *WiFiClientAssociationTelemetry) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.WiFi) == 0 {
			reason := "no_wifi_association_source"
			if !corpus.InfraEnabled {
				reason = "passive_infra_disabled"
			}
			emitObservation(emit, s.Name(), t, "wifi_client_profile_status", "unavailable", passiveStatusDetails(corpus, "infra_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.WiFi {
			quality, ok := passiveMatchIdentity(t, ev.ClientIP, ev.ClientMAC, ev.Hostname)
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "infra_passive", stat, nil)
			if ev.State != "" {
				emitObservation(emit, s.Name(), t, "wifi_assoc_state", ev.State, details)
			}
			if ev.RSSI != "" {
				emitObservation(emit, s.Name(), t, "wifi_assoc_rssi", ev.RSSI, details)
			}
			if ev.Band != "" {
				emitObservation(emit, s.Name(), t, "wifi_assoc_band", ev.Band, details)
			}
			if ev.Channel != "" {
				emitObservation(emit, s.Name(), t, "wifi_assoc_channel", ev.Channel, details)
			}
			if ev.SessionDuration != "" {
				emitObservation(emit, s.Name(), t, "wifi_assoc_session_duration", ev.SessionDuration, details)
			}
			if ev.RoamCount != "" {
				emitObservation(emit, s.Name(), t, "wifi_roam_count", ev.RoamCount, details)
			}
			emitted = true
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "wifi_client_profile_status", "observed", passiveObservationDetails(corpus, bestQuality, "infra_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "wifi_client_profile_status", "not_seen", passiveStatusDetails(corpus, "infra_passive", "target_not_seen_in_wifi_assoc", nil))
	}
}
