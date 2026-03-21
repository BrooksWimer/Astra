package strategy

type CdpControl struct{}

func (s *CdpControl) Name() string {
	return "cdp_control"
}

func (s *CdpControl) Collect(targets []Target, emit ObservationSink) {
	outputs := collectL2NeighborOutputs()
	for _, t := range targets {
		collectNeighborObservations("cdp_control", "cdp", t, emit, outputs)
	}
}
