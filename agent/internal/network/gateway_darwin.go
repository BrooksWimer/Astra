//go:build darwin

package network

import (
	"net"

	"golang.org/x/net/route"
)

func getDefaultGateway() string {
	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return ""
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return ""
	}
	for _, m := range msgs {
		if rm, ok := m.(*route.RouteMessage); ok && rm.Version == 3 {
			for _, a := range rm.Addrs {
				if ga, ok := a.(*route.Inet4Addr); ok {
					ip := net.IPv4(ga.IP[0], ga.IP[1], ga.IP[2], ga.IP[3])
					if !ip.IsUnspecified() {
						return ip.String()
					}
				}
			}
		}
	}
	return ""
}
