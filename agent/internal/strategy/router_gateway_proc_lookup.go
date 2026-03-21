package strategy

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type routerGatewayProcLookupStrategy struct{}

func NewRouterGatewayProcLookup() Strategy { return routerGatewayProcLookupStrategy{} }
func NewRouterGateway() Strategy            { return routerGatewayProcLookupStrategy{} }

func (s routerGatewayProcLookupStrategy) Name() string { return "router_gateway_proc_lookup" }

func (s routerGatewayProcLookupStrategy) Collect(targets []Target, emit ObservationSink) {
	routes := readSystemRoutes()
	if len(routes) == 0 {
		emit(Observation{Strategy: s.Name(), Key: "route_status", Value: "unavailable"})
		return
	}

	if len(targets) == 0 {
		if route := chooseDefaultRoute(routes); route != nil {
			emitRoute(strategyName(s.Name()), *route, emit, "default_only")
		}
		return
	}

	for _, target := range targets {
		ip := firstIPCandidate(fmt.Sprint(target))
		route := selectBestRoute(routes, ip)
		if route == nil {
			emit(Observation{Strategy: s.Name(), Key: "route_status", Value: "no_match"})
			continue
		}
		emitRoute(s.Name(), *route, emit, routeStatusFor(route, ip))
	}
}

type routeEntry struct {
	Family      string
	Destination string
	Gateway     string
	Netmask     string
	Interface   string
	Metric      string
	Prefix      string
	Status      string
}

func emitRoute(strategyName string, route routeEntry, emit ObservationSink, status string) {
	if route.Gateway != "" {
		emit(Observation{Strategy: strategyName, Key: "gateway", Value: route.Gateway})
		emit(Observation{Strategy: strategyName, Key: "route_gateway", Value: route.Gateway})
	}
	if route.Interface != "" {
		emit(Observation{Strategy: strategyName, Key: "route_interface", Value: route.Interface})
	}
	if route.Metric != "" {
		emit(Observation{Strategy: strategyName, Key: "route_metric", Value: route.Metric})
	}
	if route.Family != "" {
		emit(Observation{Strategy: strategyName, Key: "route_family", Value: route.Family})
	}
	if route.Prefix != "" {
		emit(Observation{Strategy: strategyName, Key: "route_prefix", Value: route.Prefix})
	}
	if route.Destination != "" {
		emit(Observation{Strategy: strategyName, Key: "route_destination", Value: route.Destination})
	}
	if route.Netmask != "" {
		emit(Observation{Strategy: strategyName, Key: "route_netmask", Value: route.Netmask})
	}
	emit(Observation{Strategy: strategyName, Key: "route_status", Value: status})
}

func readSystemRoutes() []routeEntry {
	var commands [][]string
	switch runtime.GOOS {
	case "windows":
		commands = [][]string{{"route", "print"}}
	default:
		commands = [][]string{
			{"ip", "route", "show"},
			{"ip", "-6", "route", "show"},
			{"netstat", "-rn"},
		}
	}
	for _, args := range commands {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil || len(strings.TrimSpace(string(out))) == 0 {
			continue
		}
		if routes := parseRoutes(string(out)); len(routes) > 0 {
			return routes
		}
	}

	if routes := parseProcNetRoute(); len(routes) > 0 {
		return routes
	}
	return nil
}

func parseRoutes(output string) []routeEntry {
	switch {
	case strings.Contains(output, "Kernel IP routing table"), strings.Contains(output, "Destination        Gateway"), strings.Contains(output, "Iface"):
		return parseIPRouteShow(output)
	default:
		routes := parseIPRouteShow(output)
		if len(routes) > 0 {
			return routes
		}
		return parseNetstatRoutes(output)
	}
}

func parseIPRouteShow(output string) []routeEntry {
	var routes []routeEntry
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		r := routeEntry{Status: "parsed"}
		switch fields[0] {
		case "default":
			r.Destination = "default"
			if strings.Contains(line, ":") {
				r.Prefix = "::/0"
				r.Family = "ipv6"
			} else {
				r.Prefix = "0.0.0.0/0"
				r.Family = "ipv4"
			}
		default:
			if strings.Contains(fields[0], ":") {
				r.Family = "ipv6"
			} else {
				r.Family = "ipv4"
			}
			r.Destination = fields[0]
			if strings.Contains(fields[0], "/") {
				r.Prefix = fields[0]
			}
		}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					r.Gateway = fields[i+1]
				}
			case "dev":
				if i+1 < len(fields) {
					r.Interface = fields[i+1]
				}
			case "metric":
				if i+1 < len(fields) {
					r.Metric = fields[i+1]
				}
			}
		}
		if r.Prefix == "" && strings.Contains(r.Destination, "/") {
			r.Prefix = r.Destination
		}
		routes = append(routes, r)
	}
	return routes
}

func parseNetstatRoutes(output string) []routeEntry {
	var routes []routeEntry
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Destination") || strings.HasPrefix(line, "Routing") || strings.HasPrefix(line, "Internet") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		r := routeEntry{Destination: fields[0], Gateway: fields[1], Interface: fields[len(fields)-1], Status: "parsed"}
		r.Family = "ipv4"
		if strings.Contains(r.Destination, ":") || strings.Contains(r.Gateway, ":") {
			r.Family = "ipv6"
		}
		if strings.Contains(r.Destination, "/") {
			r.Prefix = r.Destination
		}
		routes = append(routes, r)
	}
	return routes
}

func parseProcNetRoute() []routeEntry {
	data, err := exec.Command("cat", "/proc/net/route").CombinedOutput()
	if err != nil || len(data) == 0 {
		return nil
	}
	var routes []routeEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Iface") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		dest := parseProcHexIPv4(fields[1])
		gateway := parseProcHexIPv4(fields[2])
		mask := parseProcHexIPv4(fields[7])
		metric := fields[6]
		prefix := dest
		if mask != "" {
			if ones := maskToPrefixLen(mask); ones > 0 {
				prefix = fmt.Sprintf("%s/%d", dest, ones)
			} else if dest == "0.0.0.0" {
				prefix = "0.0.0.0/0"
			}
		}
		routes = append(routes, routeEntry{
			Family:      "ipv4",
			Destination: dest,
			Gateway:     gateway,
			Netmask:     mask,
			Interface:   fields[0],
			Metric:      metric,
			Prefix:      prefix,
			Status:      "proc",
		})
	}
	return routes
}

func maskToPrefixLen(mask string) int {
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return 0
	}
	ones, _ := net.IPMask(ip).Size()
	return ones
}

func parseProcHexIPv4(hexValue string) string {
	v, err := strconv.ParseUint(hexValue, 16, 32)
	if err != nil {
		return ""
	}
	b1 := byte(v)
	b2 := byte(v >> 8)
	b3 := byte(v >> 16)
	b4 := byte(v >> 24)
	return net.IPv4(b1, b2, b3, b4).String()
}

func chooseDefaultRoute(routes []routeEntry) *routeEntry {
	for _, route := range routes {
		if route.Destination == "default" || route.Prefix == "0.0.0.0/0" || route.Prefix == "::/0" {
			r := route
			return &r
		}
	}
	if len(routes) == 0 {
		return nil
	}
	r := routes[0]
	return &r
}

func selectBestRoute(routes []routeEntry, ip net.IP) *routeEntry {
	if ip == nil {
		return chooseDefaultRoute(routes)
	}
	var candidates []routeEntry
	for _, route := range routes {
		if routeMatchesIP(route, ip) {
			candidates = append(candidates, route)
		}
	}
	if len(candidates) == 0 {
		return chooseDefaultRoute(routes)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return routeSpecificity(candidates[i]) > routeSpecificity(candidates[j])
	})
	r := candidates[0]
	return &r
}

func routeMatchesIP(route routeEntry, ip net.IP) bool {
	if route.Prefix != "" {
		if _, cidr, err := net.ParseCIDR(route.Prefix); err == nil {
			return cidr.Contains(ip)
		}
	}
	if route.Destination == "default" {
		return true
	}
	if route.Destination != "" && strings.Contains(route.Destination, "/") {
		if _, cidr, err := net.ParseCIDR(route.Destination); err == nil {
			return cidr.Contains(ip)
		}
	}
	return false
}

func routeSpecificity(route routeEntry) int {
	if route.Prefix != "" {
		if _, cidr, err := net.ParseCIDR(route.Prefix); err == nil {
			ones, _ := cidr.Mask.Size()
			return ones
		}
	}
	if route.Destination == "default" {
		return 0
	}
	if strings.Contains(route.Destination, "/") {
		if _, cidr, err := net.ParseCIDR(route.Destination); err == nil {
			ones, _ := cidr.Mask.Size()
			return ones
		}
	}
	return 1
}

func routeStatusFor(route *routeEntry, ip net.IP) string {
	if route == nil {
		return "no_match"
	}
	if route.Destination == "default" || route.Prefix == "0.0.0.0/0" || route.Prefix == "::/0" {
		return "default"
	}
	if ip == nil {
		return "selected"
	}
	return "selected"
}

func firstIPCandidate(raw string) net.IP {
	ips := extractIPCandidates(raw)
	if len(ips) == 0 {
		return nil
	}
	return net.ParseIP(ips[0])
}

var ipCandidatePattern = regexp.MustCompile(`(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}\b`)

func extractIPCandidates(raw string) []string {
	matches := ipCandidatePattern.FindAllString(raw, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if ip := net.ParseIP(strings.Trim(match, "[](),")); ip != nil {
			out = append(out, ip.String())
		}
	}
	return uniqueStrings(out)
}

func strategyName(name string) string {
	return name
}
