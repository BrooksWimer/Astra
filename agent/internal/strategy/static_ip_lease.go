package strategy

type staticIPLeaseStrategy struct{}

func NewStaticIPLease() Strategy   { return staticIPLeaseStrategy{} }
func NewStaticIpLease() Strategy    { return staticIPLeaseStrategy{} }
func NewStaticIPLeaseStrategy() Strategy { return staticIPLeaseStrategy{} }

func (s staticIPLeaseStrategy) Name() string { return "static_ip_lease" }

func (s staticIPLeaseStrategy) Collect(targets []Target, emit ObservationSink) {
	collectDHCPLeaseFamily(s.Name(), targets, emit, dhcpLeaseFamilyStatic)
}
