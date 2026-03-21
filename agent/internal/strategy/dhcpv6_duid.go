package strategy

type dhcpv6DUIDStrategy struct{}

func NewDHCPV6DUID() Strategy  { return dhcpv6DUIDStrategy{} }
func NewDHCPv6DUID() Strategy  { return dhcpv6DUIDStrategy{} }
func NewDHCPV6DuID() Strategy   { return dhcpv6DUIDStrategy{} }
func NewDHCPv6DuID() Strategy   { return dhcpv6DUIDStrategy{} }

func (s dhcpv6DUIDStrategy) Name() string { return "dhcpv6_duid" }

func (s dhcpv6DUIDStrategy) Collect(targets []Target, emit ObservationSink) {
	collectDHCPLeaseFamily(s.Name(), targets, emit, dhcpLeaseFamilyV6)
}
