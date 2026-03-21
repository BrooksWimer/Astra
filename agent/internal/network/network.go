package network

import (
	"net"
)

// NetworkFacts is the full set of facts about the selected interface and LAN.
type NetworkFacts struct {
	Iface         IfaceFacts
	LocalIP       string
	Netmask       string
	CIDR          string // e.g. "10.0.0.0/24"
	Broadcast     string
	GatewayIP     string
	IsLargeSubnet bool // true if /16 or larger (need throttle/sampling)
}

// IfaceFacts describes the selected network interface.
type IfaceFacts struct {
	Name string
	MAC  string
}

// Info holds primary interface and network facts (backward compatible).
type Info struct {
	LocalIP       string
	Subnet        string // CIDR, e.g. "10.0.0.95/24"
	GatewayIP     string
	InterfaceName string
	InterfaceMAC  string
	Netmask       string
	Broadcast     string
	IsLargeSubnet bool
}

// PrimaryInterface returns the first Up, non-loopback interface with IPv4 and default route.
func PrimaryInterface() (iface *net.Interface, info *Info, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	gateway := getDefaultGateway()
	if gateway == "" {
		gateway = "0.0.0.0"
	}

	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 || ifaces[i].Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifaces[i].Addrs()
		var ipnet *net.IPNet
		var ip string
		networkIP := ""
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				ipnet = ipn
				ip = ipn.IP.String()
				networkIP = ipn.IP.Mask(ipn.Mask).String()
				break
			}
		}
		if ipnet == nil {
			continue
		}
		mask := ipnet.Mask
		ones, bits := mask.Size()
		var cidr string
		if bits == 32 {
			cidr = networkIP + "/" + itoa(ones)
		} else {
			cidr = ipnet.String()
		}
		netmask := maskToString(mask)
		broadcast := broadcastAddr(ipnet)
		isLarge := ones <= 16
		mac := ""
		if ifaces[i].HardwareAddr != nil {
			mac = ifaces[i].HardwareAddr.String()
		}
		return &ifaces[i], &Info{
			LocalIP:       ip,
			Subnet:        cidr,
			GatewayIP:     gateway,
			InterfaceName: ifaces[i].Name,
			InterfaceMAC:  mac,
			Netmask:       netmask,
			Broadcast:     broadcast,
			IsLargeSubnet: isLarge,
		}, nil
	}
	return nil, nil, nil
}

func maskToString(m net.IPMask) string {
	if len(m) < 4 {
		return ""
	}
	// Avoid importing fmt; format dotted decimal manually
	b := make([]byte, 0, 15)
	for i := 0; i < 4; i++ {
		if i > 0 {
			b = append(b, '.')
		}
		b = append(b, itoa(int(m[i]))...)
	}
	return string(b)
}

func broadcastAddr(ipnet *net.IPNet) string {
	ip := ipnet.IP.To4()
	if ip == nil {
		return ""
	}
	mask := ipnet.Mask
	out := make(net.IP, 4)
	for i := range ip {
		out[i] = ip[i] | ^mask[i]
	}
	return out.String()
}

// ToNetworkFacts converts Info to NetworkFacts for API/output.
func (i *Info) ToNetworkFacts() NetworkFacts {
	return NetworkFacts{
		Iface:         IfaceFacts{Name: i.InterfaceName, MAC: i.InterfaceMAC},
		LocalIP:       i.LocalIP,
		Netmask:       i.Netmask,
		CIDR:          i.Subnet,
		Broadcast:     i.Broadcast,
		GatewayIP:     i.GatewayIP,
		IsLargeSubnet: i.IsLargeSubnet,
	}
}

func itoa(i int) string {
	if i < 0 {
		return "0"
	}
	var b [4]byte
	n := 0
	for i >= 10 {
		b[3-n] = byte('0' + i%10)
		i /= 10
		n++
	}
	b[3-n] = byte('0' + i)
	n++
	return string(b[4-n : 4])
}

// ParseCIDRSubnet returns "x.x.x.x/yy" for the given IP and mask.
func ParseCIDRSubnet(ip net.IP, mask net.IPMask) string {
	if ip = ip.To4(); ip == nil {
		return ""
	}
	ones, _ := mask.Size()
	return ip.String() + "/" + itoa(ones)
}

// FirstIPInSubnet returns the first usable IP in the subnet (network + 1 for /24).
func FirstIPInSubnet(ipnet *net.IPNet) net.IP {
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil
	}
	out := make(net.IP, 4)
	copy(out, ip)
	out[3]++
	return out
}

// EnumerateSubnet returns all IPs in the given CIDR (excluding network/broadcast).
func EnumerateSubnet(cidr string) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	ip := make(net.IP, 4)
	copy(ip, ipnet.IP.To4())
	broadcastStr := broadcastAddr(ipnet)
	for {
		ip[3]++
		if !ipnet.Contains(ip) {
			break
		}
		// Wrapped back to network address (e.g. .255 -> .0)
		if ip.Equal(ipnet.IP) {
			break
		}
		// Exclude broadcast address
		if ip.String() == broadcastStr {
			break
		}
		next := make(net.IP, 4)
		copy(next, ip)
		ips = append(ips, next)
	}
	return ips, nil
}
