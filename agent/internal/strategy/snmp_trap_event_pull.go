package strategy

type SnmpTrapEventPull struct{}

func (s *SnmpTrapEventPull) Name() string {
	return "snmp_trap_event_pull"
}

func (s *SnmpTrapEventPull) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		emitObservation(emit, s.Name(), t, "snmp_trap", "unavailable", map[string]string{
			"reason":    "no_trap_listener",
			"transport": "udp",
			"port":      "162",
		})
	}
}
