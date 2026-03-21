package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

// Advertise registers the agent as _netwise._tcp on the local network.
func Advertise(port int, version, deviceName string) (*zeroconf.Server, error) {
	text := []string{"version=" + version}
	if deviceName != "" {
		text = append(text, "name="+deviceName)
	}
	server, err := zeroconf.Register("Netwise Agent", "_netwise._tcp", "local.", port, text, nil)
	if err != nil {
		return nil, fmt.Errorf("zeroconf register: %w", err)
	}
	log.Printf("mDNS: advertising _netwise._tcp on port %d", port)
	return server, nil
}

// Entry is a discovered mDNS service: IP, hostname, and service type.
type Entry struct {
	IP        string
	Hostname  string
	Service   string // e.g. _googlecast._tcp
	Instance  string
}

// DefaultBrowseServices are service types to browse for device discovery.
var DefaultBrowseServices = []string{
	"_netwise._tcp",
	"_googlecast._tcp",
	"_ipp._tcp",
	"_printer._tcp",
	"_ipps._tcp",
	"_http._tcp",
	"_workstation._tcp",
	"_smb._tcp",
	"_afpovertcp._tcp",
	"_spotify-connect._tcp",
	"_raop._tcp",
	"_hap._tcp",
	"_home-sharing._tcp",
}

// Browse discovers mDNS services for the given types and returns entries (IP, hostname, service).
// If iface is non-nil, the resolver is bound to that interface (required on Windows for correct multicast).
// Each service type is browsed in parallel; timeout applies to the whole operation.
func Browse(ctx context.Context, iface *net.Interface, serviceTypes []string, timeout time.Duration) []Entry {
	if len(serviceTypes) == 0 {
		serviceTypes = DefaultBrowseServices
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var opts []zeroconf.ClientOption
	if iface != nil {
		opts = append(opts, zeroconf.SelectIfaces([]net.Interface{*iface}))
	}
	resolver, err := zeroconf.NewResolver(opts...)
	if err != nil {
		log.Printf("mDNS: resolver init failed: %v", err)
		return nil
	}
	var mu sync.Mutex
	byKey := make(map[string]*Entry) // key = IP + "\t" + service to merge hostname/services per IP
	var wg sync.WaitGroup
	domain := "local."
	for _, svc := range serviceTypes {
		svc := svc
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries := make(chan *zeroconf.ServiceEntry)
			go func() {
				for entry := range entries {
					if entry == nil {
						continue
					}
					var ip string
					if len(entry.AddrIPv4) > 0 {
						ip = entry.AddrIPv4[0].String()
					}
					if ip == "" {
						continue
					}
					hostname := strings.TrimSuffix(entry.HostName, ".")
					service := strings.TrimSuffix(entry.Service, ".")
					key := ip + "\t" + service
					mu.Lock()
					if e, ok := byKey[key]; ok {
						if hostname != "" {
							e.Hostname = hostname
						}
						if e.Instance == "" && entry.Instance != "" {
							e.Instance = entry.Instance
						}
					} else {
						byKey[key] = &Entry{IP: ip, Hostname: hostname, Service: service, Instance: entry.Instance}
					}
					mu.Unlock()
				}
			}()
			if err := resolver.Browse(ctx, svc, domain, entries); err != nil {
				log.Printf("mDNS: browse %q failed: %v", svc, err)
			}
		}()
	}
	<-ctx.Done()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	out := make([]Entry, 0, len(byKey))
	for _, e := range byKey {
		out = append(out, *e)
	}
	return out
}
