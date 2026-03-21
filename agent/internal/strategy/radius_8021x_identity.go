package strategy

type Radius8021xIdentity struct{}

func (s *Radius8021xIdentity) Name() string {
	return "radius_8021x_identity"
}

func (s *Radius8021xIdentity) Collect(targets []Target, emit ObservationSink) {
	corpus := passiveCorpus()
	for _, t := range targets {
		if len(corpus.Radius) == 0 {
			reason := "no_radius_identity_source"
			if !corpus.InfraEnabled {
				reason = "passive_infra_disabled"
			}
			emitObservation(emit, s.Name(), t, "radius_auth_result", "unavailable", passiveStatusDetails(corpus, "infra_passive", reason, nil))
			continue
		}
		emitted := false
		var best passiveWindowStat
		bestQuality := ""
		for _, ev := range corpus.Radius {
			quality, ok := passiveMatchIdentity(t, ev.ClientIP, ev.ClientMAC, ev.Identity)
			if !ok {
				continue
			}
			stat := passiveWindowStat{}
			stat.Add(ev.Timestamp)
			details := passiveObservationDetails(corpus, quality, "infra_passive", stat, nil)
			if ev.Identity != "" {
				emitObservation(emit, s.Name(), t, "radius_identity", ev.Identity, details)
			}
			if ev.Realm != "" {
				emitObservation(emit, s.Name(), t, "radius_realm", ev.Realm, details)
			}
			if ev.EAPType != "" {
				emitObservation(emit, s.Name(), t, "radius_eap_type", ev.EAPType, details)
			}
			if ev.VLAN != "" {
				emitObservation(emit, s.Name(), t, "radius_vlan", ev.VLAN, details)
			}
			if ev.Role != "" {
				emitObservation(emit, s.Name(), t, "radius_role", ev.Role, details)
			}
			if ev.AuthResult != "" {
				emitObservation(emit, s.Name(), t, "radius_auth_result", ev.AuthResult, details)
			}
			emitted = true
			best.Add(ev.Timestamp)
			bestQuality = quality
		}
		if emitted {
			emitObservation(emit, s.Name(), t, "radius_auth_result", "observed", passiveObservationDetails(corpus, bestQuality, "infra_passive", best, nil))
			continue
		}
		emitObservation(emit, s.Name(), t, "radius_auth_result", "not_seen", passiveStatusDetails(corpus, "infra_passive", "target_not_seen_in_radius", nil))
	}
}
