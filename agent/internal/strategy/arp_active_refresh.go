package strategy

type arpActiveRefreshStrategy struct{}

func NewARPActiveRefresh() Strategy       { return arpActiveRefreshStrategy{} }
func NewArpActiveRefresh() Strategy       { return arpActiveRefreshStrategy{} }
func NewARPActiveRefreshStrategy() Strategy { return arpActiveRefreshStrategy{} }

func (s arpActiveRefreshStrategy) Name() string { return "arp_active_refresh" }

func (s arpActiveRefreshStrategy) Collect(targets []Target, emit ObservationSink) {
	collectARPNeighbors(s.Name(), targets, emit, true)
}
