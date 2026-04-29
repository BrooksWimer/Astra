package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/netwise/agent/internal/arp"
	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/labeling"
	"github.com/netwise/agent/internal/mdns"
	"github.com/netwise/agent/internal/network"
	"github.com/netwise/agent/internal/oui"
	"github.com/netwise/agent/internal/ssdp"
	"github.com/netwise/agent/internal/store"
	"github.com/netwise/agent/internal/strategy"
)

type Scanner struct {
	netInfo *network.Info
	cfg     *config.Config
	store   *store.Store
	scanID  string
	// strategies is the list of strategies to execute during strategy observation collection.
	strategies   []strategy.Strategy
	strategyRuns []StrategyRunStat
}

type StrategyRunStat struct {
	Strategy            string `json:"strategy"`
	DurationMs          int64  `json:"duration_ms"`
	EmittedObservations int    `json:"emitted_observations"`
	Panicked            bool   `json:"panicked,omitempty"`
}

func New(netInfo *network.Info, cfg *config.Config, st *store.Store, scanID string) *Scanner {
	return NewWithStrategyFilter(netInfo, cfg, st, scanID, nil)
}

func NewWithStrategyFilter(netInfo *network.Info, cfg *config.Config, st *store.Store, scanID string, strategyNames []string) *Scanner {
	resolvedNames := strategyNames
	if len(resolvedNames) == 0 && cfg != nil {
		resolvedNames = strategy.ProfileStrategyNames(cfg.StrategyProfile)
	}
	return &Scanner{
		netInfo:    netInfo,
		cfg:        cfg,
		store:      st,
		scanID:     scanID,
		strategies: strategy.ResolveStrategies(resolvedNames),
	}
}

func (s *Scanner) Run() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.ScanTimeoutSeconds)*time.Second)
	defer cancel()
	localIP := ""
	ifaceName := ""
	if s.netInfo != nil {
		localIP = s.netInfo.LocalIP
		ifaceName = s.netInfo.InterfaceName
	}
	strategy.SetRuntimeConfig(s.cfg)
	defer strategy.SetRuntimeConfig(nil)
	strategy.StartPassiveRuntime(s.cfg, localIP, ifaceName)
	defer strategy.StopPassiveRuntime()

	s.store.EmitProgress(s.scanID, "Reading ARP table...")
	arpMap, err := arp.Table()
	if err != nil {
		log.Printf("[scan %s] ARP read failed: %v", s.scanID, err)
		s.store.EmitProgress(s.scanID, "ARP read failed; doing probe sweep")
	}
	if arpMap == nil {
		arpMap = make(map[string]string)
	}
	initialCount := len(arpMap)
	if initialCount > 0 {
		log.Printf("[scan %s] ARP table: %d entries (cached)", s.scanID, initialCount)
	}

	ips, errEnum := network.EnumerateSubnet(s.netInfo.Subnet)
	if errEnum != nil {
		log.Printf("[scan %s] Subnet enum failed: %v", s.scanID, errEnum)
		s.store.EmitProgress(s.scanID, "Subnet enum failed")
		return
	}
	sweepIPs := ips
	if s.netInfo.IsLargeSubnet && s.cfg.MaxProbeIPs > 0 && len(sweepIPs) > s.cfg.MaxProbeIPs {
		sweepIPs = ips[:s.cfg.MaxProbeIPs]
	}
	if len(sweepIPs) > 0 {
		s.store.EmitProgress(s.scanID, "ARP sweep (pinging subnet)...")
		sweepMap, errSweep := arp.Sweep(ctx, sweepIPs)
		if errSweep != nil {
			log.Printf("[scan %s] ARP sweep failed: %v", s.scanID, errSweep)
		} else if len(sweepMap) > len(arpMap) {
			arpMap = sweepMap
			log.Printf("[scan %s] ARP sweep: %d entries (was %d cached)", s.scanID, len(arpMap), initialCount)
		}
	}
	for ip, mac := range arpMap {
		s.upsertDevice(ip, mac)
	}
	if len(arpMap) > 0 {
		log.Printf("[scan %s] ARP: %d devices", s.scanID, len(arpMap))
	}

	// mDNS and SSDP discovery (parallel), bound to primary interface so they work on Windows
	s.store.EmitProgress(s.scanID, "Discovering mDNS and SSDP...")
	var mdnsEntries []mdns.Entry
	var ssdpEntries []ssdp.Entry
	var dwg sync.WaitGroup
	primaryIface := s.primaryInterface()
	dwg.Add(2)
	go func() {
		defer dwg.Done()
		mdnsEntries = mdns.Browse(ctx, primaryIface, nil, 5*time.Second)
		log.Printf("[scan %s] mDNS: found %d services", s.scanID, len(mdnsEntries))
	}()
	go func() {
		defer dwg.Done()
		bindIP := ""
		if s.netInfo != nil {
			bindIP = s.netInfo.LocalIP
		}
		ssdpEntries = ssdp.Discover(ctx, bindIP, 3*time.Second)
		log.Printf("[scan %s] SSDP: found %d responses", s.scanID, len(ssdpEntries))
	}()
	dwg.Wait()
	strategy.SeedMDNSCache(mdnsEntries)
	strategy.SeedSSDPCache(ssdpEntries)
	for _, e := range mdnsEntries {
		s.upsertDeviceFromMDNS(e)
	}
	// Fetch SSDP LOCATION XML for device description (manufacturer, model, friendlyName)
	descByIP := s.fetchSSDPDescriptions(ctx, ssdpEntries)
	ssdpUniqueIPs := make(map[string]struct{})
	for _, e := range ssdpEntries {
		ssdpUniqueIPs[e.IP] = struct{}{}
		s.upsertDeviceFromSSDP(e, descByIP[e.IP])
	}
	if len(ssdpEntries) > 0 {
		log.Printf("[scan %s] SSDP: %d unique IPs (merged into device list)", s.scanID, len(ssdpUniqueIPs))
	}

	// Probe sweep to discover more hosts (TCP connect to common ports)
	if s.netInfo.IsLargeSubnet && s.cfg.MaxProbeIPs > 0 && len(ips) > s.cfg.MaxProbeIPs {
		ips = ips[:s.cfg.MaxProbeIPs]
		log.Printf("[scan %s] Large subnet: probing first %d IPs", s.scanID, len(ips))
	}
	s.store.EmitProgress(s.scanID, "Probing hosts...")
	const workers = 32
	ch := make(chan net.IP, len(ips))
	for _, ip := range ips {
		ch <- ip
	}
	close(ch)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ch {
				if ctx.Err() != nil {
					return
				}
				if ip.String() == s.netInfo.LocalIP {
					continue
				}
				if port := probe(ip); port > 0 {
					mac := arpMap[ip.String()]
					s.upsertDeviceFromProbe(ip.String(), mac, port)
				}
			}
		}()
	}
	wg.Wait()

	if s.cfg.EnablePortScan {
		s.store.EmitProgress(s.scanID, "Port scan (optional)...")
		s.portScan(ctx)
	}

	s.store.EmitProgress(s.scanID, "Enriching service fingerprints...")
	s.enrichFingerprints(ctx)

	s.store.EmitProgress(s.scanID, "Enriching NetBIOS names...")
	s.enrichNetBIOS(ctx)

	s.store.EmitProgress(s.scanID, "Collecting strategy observations...")
	strategyCtx := ctx
	var strategyCancel context.CancelFunc
	if ctx.Err() != nil {
		timeout := strategyCollectionTimeout(s.cfg)
		log.Printf("[scan %s] scan budget expired before strategy collection; extending strategy phase by %s to preserve raw evidence", s.scanID, timeout)
		strategyCtx, strategyCancel = context.WithTimeout(context.Background(), timeout)
	}
	if strategyCancel != nil {
		defer strategyCancel()
	}
	s.collectStrategyObservations(strategyCtx)

	s.store.EmitProgress(s.scanID, "Done")
	res := s.store.GetScanResult(s.scanID)
	if res != nil {
		log.Printf("[scan %s] Finished: %d devices", s.scanID, len(res.Devices))
	}
}

func probe(ip net.IP) int {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "80"), 500*time.Millisecond)
	if err == nil {
		c.Close()
		return 80
	}
	c, err = net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "443"), 500*time.Millisecond)
	if err == nil {
		c.Close()
		return 443
	}
	c, err = net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "22"), 300*time.Millisecond)
	if err == nil {
		c.Close()
		return 22
	}
	// ICMP would require raw socket; TCP connect is safe
	return 0
}

func strategyCollectionTimeout(cfg *config.Config) time.Duration {
	const minimum = 45 * time.Second
	if cfg == nil || cfg.ScanTimeoutSeconds <= 0 {
		return minimum
	}
	timeout := time.Duration(cfg.ScanTimeoutSeconds) * time.Second
	if timeout < minimum {
		return minimum
	}
	return timeout
}

func (s *Scanner) portScan(ctx context.Context) {
	devices := s.store.GetLatestDevices()
	for _, d := range devices {
		var open []int
		for _, port := range s.cfg.PortsToCheck {
			if ctx.Err() != nil {
				return
			}
			c, err := net.DialTimeout("tcp", net.JoinHostPort(d.IP, itoa(port)), 500*time.Millisecond)
			if err == nil {
				c.Close()
				open = append(open, port)
			}
		}
		d.PortsOpen = mergeIntSlices(d.PortsOpen, open)
		flags := make([]string, len(d.Flags), len(d.Flags)+1)
		copy(flags, d.Flags)
		for _, p := range open {
			if p == 445 || p == 3389 {
				flags = append(flags, "risky_ports")
				break
			}
		}
		d.Flags = flags
		d = s.recomputeClassification(d)
		s.store.AddOrUpdateDevice(s.scanID, d)
	}
}

func itoa(i int) string {
	if i <= 0 {
		return "0"
	}
	var b [8]byte
	n := 0
	for i > 0 {
		b[7-n] = byte('0' + i%10)
		i /= 10
		n++
	}
	return string(b[8-n : 8])
}

func (s *Scanner) upsertDevice(ip, mac string) {
	s.upsertDeviceWithSourcesAndPorts(ip, mac, []string{"arp"}, nil)
}

func (s *Scanner) upsertDeviceFromProbe(ip, mac string, openPort int) {
	ports := []int{}
	if openPort > 0 {
		ports = append(ports, openPort)
	}
	s.upsertDeviceWithSourcesAndPorts(ip, mac, []string{"tcp_probe"}, ports)
}

func (s *Scanner) upsertDeviceWithSourcesAndPorts(ip, mac string, sources []string, openPorts []int) {
	if !s.shouldTrackIP(ip) {
		return
	}

	existing := s.deviceByIP(ip)
	id := mac
	if id == "" {
		id = "ip_" + ip
	}
	if existing != nil && existing.ID != "" {
		id = existing.ID
	}
	vendor := oui.Lookup(mac)
	macIsLocallyAdmin := oui.IsLocallyAdministeredMAC(mac)
	hostname := ""
	if existing != nil && existing.Hostname != nil {
		hostname = *existing.Hostname
	}
	if hostname == "" {
		hostname = reverseDNS(ip)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	d := store.Device{
		ID:                id,
		IP:                ip,
		MAC:               mac,
		Vendor:            vendor,
		MACIsLocallyAdmin: macIsLocallyAdmin,
		Hostname:          strPtr(hostname),
		ProtocolsSeen:     store.ProtocolsSeen{MDNS: []string{}, SSDP: []string{}, NetBIOS: []string{}},
		PortsOpen:         nil,
		FirstSeen:         now,
		LastSeen:          now,
		Flags:             []string{},
		SourcesSeen:       sources,
	}
	if existing != nil {
		d.FirstSeen = existing.FirstSeen
		d.ProtocolsSeen = existing.ProtocolsSeen
		d.PortsOpen = existing.PortsOpen
		d.Flags = existing.Flags
		if d.MAC == "" {
			d.MAC = existing.MAC
		}
		if existing.Vendor != "" && existing.Vendor != "Unknown" {
			d.Vendor = existing.Vendor
		}
		if existing.MACIsLocallyAdmin {
			d.MACIsLocallyAdmin = true
		}
		d.HTTPServer = existing.HTTPServer
		d.SSDPServer = existing.SSDPServer
		d.TLSSubject = existing.TLSSubject
		d.TLSIssuer = existing.TLSIssuer
		d.TLSSANS = existing.TLSSANS
		d.SSHBanner = existing.SSHBanner
	}
	d.PortsOpen = mergeIntSlices(d.PortsOpen, openPorts)
	d.SourcesSeen = mergeStringSlices(d.SourcesSeen, sources)
	d = s.recomputeClassification(d)
	s.store.AddOrUpdateDevice(s.scanID, d)
}

// primaryInterface returns the primary network interface for multicast (mDNS/SSDP), or nil for all interfaces.
func (s *Scanner) primaryInterface() *net.Interface {
	if s.netInfo == nil || s.netInfo.InterfaceName == "" {
		return nil
	}
	iface, err := net.InterfaceByName(s.netInfo.InterfaceName)
	if err != nil {
		return nil
	}
	return iface
}

// fetchSSDPDescriptions fetches LOCATION URLs from SSDP entries (deduped by URL), parses UPnP XML, returns map IP -> description.
func (s *Scanner) fetchSSDPDescriptions(ctx context.Context, entries []ssdp.Entry) map[string]*ssdp.DeviceDescription {
	seenURL := make(map[string]string) // URL -> IP (first IP we saw for this URL)
	for _, e := range entries {
		if e.Location == "" {
			continue
		}
		if _, ok := seenURL[e.Location]; !ok {
			seenURL[e.Location] = e.IP
		}
	}
	if len(seenURL) == 0 {
		return nil
	}
	descByIP := make(map[string]*ssdp.DeviceDescription)
	var mu sync.Mutex
	const fetchWorkers = 5
	const fetchTimeout = 3 * time.Second
	urlCh := make(chan string, len(seenURL))
	for u := range seenURL {
		urlCh <- u
	}
	close(urlCh)
	var wg sync.WaitGroup
	for i := 0; i < fetchWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for locationURL := range urlCh {
				if ctx.Err() != nil {
					return
				}
				desc := ssdp.FetchDeviceDescription(ctx, locationURL, fetchTimeout)
				if desc == nil {
					continue
				}
				ip := seenURL[locationURL]
				mu.Lock()
				if existing := descByIP[ip]; existing == nil || (desc.Manufacturer != "" && existing.Manufacturer == "") {
					descByIP[ip] = desc
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(descByIP) > 0 {
		log.Printf("[scan %s] SSDP: fetched %d device descriptions (manufacturer/model/friendlyName)", s.scanID, len(descByIP))
	}
	return descByIP
}

// deviceByIP returns an existing device with the given IP, or nil.
func (s *Scanner) deviceByIP(ip string) *store.Device {
	for _, d := range s.store.GetLatestDevices() {
		if d.IP == ip {
			return &d
		}
	}
	return nil
}

func (s *Scanner) enrichFingerprints(ctx context.Context) {
	devices := s.store.GetLatestDevices()
	if len(devices) == 0 {
		return
	}

	type target struct {
		device store.Device
	}
	targets := make(chan target, len(devices))
	for _, d := range devices {
		if !s.shouldTrackIP(d.IP) {
			continue
		}
		targets <- target{device: d}
	}
	close(targets)

	const workers = 6
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				if ctx.Err() != nil {
					return
				}
				existing := s.deviceByIP(t.device.IP)
				if existing == nil {
					continue
				}
				updated := *existing
				changed := false

				hasPort80 := containsInt(updated.PortsOpen, 80)
				hasPort443 := containsInt(updated.PortsOpen, 443)
				hasPort22 := containsInt(updated.PortsOpen, 22)

				if updated.HTTPServer == "" && (hasPort80 || hasPort443) {
					header := ""
					if hasPort443 {
						header = s.fetchHTTPServer(updated.IP, "https", 900*time.Millisecond)
					}
					if header == "" && hasPort80 {
						header = s.fetchHTTPServer(updated.IP, "http", 900*time.Millisecond)
					}
					if header != "" {
						updated.HTTPServer = header
						changed = true
					}
				}

				if hasPort443 && updated.TLSSubject == "" && updated.TLSIssuer == "" && updated.TLSSANS == "" {
					subject, issuer, sans := s.fetchTLSFingerprint(updated.IP, 900*time.Millisecond)
					if subject != "" {
						updated.TLSSubject = subject
						changed = true
					}
					if issuer != "" {
						updated.TLSIssuer = issuer
						changed = true
					}
					if sans != "" {
						updated.TLSSANS = sans
						changed = true
					}
				}

				if hasPort22 && updated.SSHBanner == "" {
					banner := s.fetchSSHBanner(updated.IP, 900*time.Millisecond)
					if banner != "" {
						updated.SSHBanner = banner
						changed = true
					}
				}

				if !changed {
					continue
				}
				updated = s.recomputeClassification(updated)
				s.store.AddOrUpdateDevice(s.scanID, updated)
			}
		}()
	}
	wg.Wait()
}

func (s *Scanner) fetchHTTPServer(ip, scheme string, timeout time.Duration) string {
	port := ""
	switch scheme {
	case "http":
		port = "80"
	case "https":
		port = "443"
	default:
		return ""
	}
	url := scheme + "://" + net.JoinHostPort(ip, port)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "netwise")
	res, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	return strings.TrimSpace(res.Header.Get("Server"))
}

func (s *Scanner) fetchTLSFingerprint(ip string, timeout time.Duration) (subject, issuer, sans string) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ip,
	})
	if err != nil {
		return "", "", ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", "", ""
	}
	cert := state.PeerCertificates[0]
	subject = strings.TrimSpace(cert.Subject.CommonName)
	if subject == "" {
		subject = strings.TrimSpace(cert.Subject.String())
	}
	issuer = strings.TrimSpace(cert.Issuer.CommonName)
	if issuer == "" {
		issuer = strings.TrimSpace(cert.Issuer.String())
	}
	seen := make(map[string]struct{})
	values := []string{}
	addSAN := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	for _, h := range cert.DNSNames {
		addSAN(h)
	}
	for _, ip := range cert.IPAddresses {
		addSAN(ip.String())
	}
	sans = strings.Join(values, ",")
	return subject, issuer, sans
}

func (s *Scanner) fetchSSHBanner(ip string, timeout time.Duration) string {
	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", net.JoinHostPort(ip, "22"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func (s *Scanner) enrichNetBIOS(ctx context.Context) {
	if runtime.GOOS != "windows" {
		return
	}
	devices := s.store.GetLatestDevices()
	type target struct {
		ip string
	}
	targets := make(chan target, len(devices))
	for _, d := range devices {
		if !s.shouldTrackIP(d.IP) {
			continue
		}
		targets <- target{ip: d.IP}
	}
	close(targets)
	const workers = 6
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				if ctx.Err() != nil {
					return
				}
				names := s.queryNetBIOSNames(t.ip)
				if len(names) == 0 {
					continue
				}
				existing := s.deviceByIP(t.ip)
				if existing == nil {
					continue
				}
				updated := *existing
				updated.ProtocolsSeen.NetBIOS = mergeStringSlices(updated.ProtocolsSeen.NetBIOS, names)
				if (updated.Hostname == nil || *updated.Hostname == "") && len(names) > 0 {
					updated.Hostname = strPtr(names[0])
				}
				updated = s.recomputeClassification(updated)
				s.store.AddOrUpdateDevice(s.scanID, updated)
			}
		}()
	}
	wg.Wait()
}

func (s *Scanner) collectStrategyObservations(ctx context.Context) {
	devices := s.store.GetLatestDevices()
	if len(devices) == 0 || ctx.Err() != nil {
		return
	}

	targets := make([]strategy.Target, 0, len(devices))
	for _, d := range devices {
		if !s.shouldTrackIP(d.IP) {
			continue
		}
		t := strategy.Target{
			IP:       d.IP,
			MAC:      d.MAC,
			Tags:     map[string]string{},
			Hostname: "",
		}
		if d.Hostname != nil {
			t.Hostname = *d.Hostname
		}
		if s.netInfo != nil && s.netInfo.GatewayIP != "" {
			t.Tags["gateway"] = s.netInfo.GatewayIP
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return
	}

	obsByIP := make(map[string][]strategy.Observation, len(targets))
	strategyEmitCount := map[string]int{}
	totalEmits := 0
	var mu sync.Mutex
	emit := func(obs strategy.Observation) {
		if obs.IP == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		obsByIP[obs.IP] = append(obsByIP[obs.IP], obs)
		strategyEmitCount[obs.Strategy]++
		totalEmits++
	}

	strategies := s.strategies
	if len(strategies) == 0 {
		strategies = strategy.DefaultStrategies()
	}
	s.strategyRuns = s.strategyRuns[:0]
	for _, strat := range strategies {
		before := strategyEmitCount[strat.Name()]
		started := time.Now()
		panicked := false
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
					log.Printf("[scan %s] strategy=%s panicked; continuing", s.scanID, strat.Name())
				}
			}()
			strat.Collect(targets, emit)
		}()
		after := strategyEmitCount[strat.Name()]
		s.strategyRuns = append(s.strategyRuns, StrategyRunStat{
			Strategy:            strat.Name(),
			DurationMs:          time.Since(started).Milliseconds(),
			EmittedObservations: after - before,
			Panicked:            panicked,
		})
		if after == before {
			log.Printf("[scan %s] strategy=%s emitted 0 observations", s.scanID, strat.Name())
		} else {
			log.Printf("[scan %s] strategy=%s emitted %d observations", s.scanID, strat.Name(), after-before)
		}
	}
	log.Printf("[scan %s] total strategy observations=%d", s.scanID, totalEmits)

	for ip, observations := range obsByIP {
		existing := s.deviceByIP(ip)
		if existing == nil {
			continue
		}
		updated := *existing
		updatedObservations := make([]store.Observation, 0, len(observations))
		for _, obs := range observations {
			updatedObservations = append(updatedObservations, store.Observation{
				Timestamp: obs.Timestamp,
				Strategy:  obs.Strategy,
				IP:        obs.IP,
				MAC:       obs.MAC,
				Hostname:  obs.Hostname,
				Key:       obs.Key,
				Value:     obs.Value,
				Details:   obs.Details,
			})
		}
		updated.Observations = updatedObservations
		updated = s.recomputeClassification(updated)
		s.store.AddOrUpdateDevice(s.scanID, updated)
		if len(obsByIP) > 0 {
			log.Printf("[scan %s] persisted observations for target=%s count=%d", s.scanID, ip, len(updatedObservations))
		}
	}
}

func (s *Scanner) StrategyNames() []string {
	strategies := s.strategies
	if len(strategies) == 0 {
		strategies = strategy.DefaultStrategies()
	}
	names := make([]string, 0, len(strategies))
	for _, strat := range strategies {
		names = append(names, strat.Name())
	}
	return names
}

func (s *Scanner) StrategyRunStats() []StrategyRunStat {
	if len(s.strategyRuns) == 0 {
		return nil
	}
	out := make([]StrategyRunStat, len(s.strategyRuns))
	copy(out, s.strategyRuns)
	return out
}

func (s *Scanner) queryNetBIOSNames(ip string) []string {
	cmd := exec.Command("nbtstat", "-A", ip)
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) == 0 {
		return nil
	}
	return parseNetBIOSNames(string(out))
}

var netbiosNameRegex = regexp.MustCompile(`(?i)^([A-Z0-9._-]{1,15})\s+<\d{2}>\s+(UNIQUE|GROUP)`)

func parseNetBIOSNames(output string) []string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	seen := make(map[string]struct{})
	var names []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		match := netbiosNameRegex.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name == "" || strings.EqualFold(name, "__MSBROWSE__") || strings.EqualFold(name, "INADDR.ARPA") {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

// recomputeClassification runs the hybrid labeler with full device signals and updates
// both legacy classification fields and the new Device.LabelState.
func (s *Scanner) recomputeClassification(d store.Device) store.Device {
	res := labeling.ClassifyDevice(d, s.cfg)
	d.DeviceType = res.DeviceCategory
	d.Confidence = res.LabelConfidence
	d.LabelState = toStoreLabelState(res)
	d.ClassificationReasons = append(
		[]string{},
		res.ReasonChain...,
	)
	if len(res.CandidateLabels) > 0 {
		reasons := make([]string, 0, len(res.CandidateLabels))
		for _, c := range res.CandidateLabels {
			if c.Label == "" || c.Confidence < 0.05 {
				continue
			}
			reasons = append(reasons, "candidate="+c.Label+":"+fmt.Sprintf("%.2f", c.Confidence))
		}
		if len(reasons) > 0 {
			d.ClassificationReasons = append(d.ClassificationReasons, reasons...)
		}
	}
	if len(d.ClassificationReasons) == 0 {
		d.ClassificationReasons = append(d.ClassificationReasons, "no identifying signals")
	}
	if d.ClassificationReasons == nil {
		d.ClassificationReasons = []string{}
	}
	d.DeviceType = res.DeviceCategory
	return d
}

func toStoreLabelState(res labeling.LabelResult) store.LabelState {
	candidates := make([]store.LabelCandidate, 0, len(res.CandidateLabels))
	for _, c := range res.CandidateLabels {
		candidates = append(candidates, store.LabelCandidate{
			Label:        c.Label,
			Score:        c.Score,
			Confidence:   c.Confidence,
			Evidence:     c.Evidence,
			SupportTiers: c.SupportTiers,
		})
	}
	return store.LabelState{
		DeviceCategory:            res.DeviceCategory,
		DeviceSubType:             res.DeviceSubType,
		LabelConfidence:           res.LabelConfidence,
		LabelConfidenceCalibrated: res.LabelConfidenceCalibrated,
		EvidenceSummary:           res.EvidenceSummary,
		CandidateLabels:           candidates,
		ReasonChain:               res.ReasonChain,
		ConflictFlags:             res.ConflictFlags,
		ConfidenceBand:            string(res.ConfidenceBand),
	}
}

func (s *Scanner) upsertDeviceFromMDNS(e mdns.Entry) {
	if !s.shouldTrackIP(e.IP) {
		return
	}
	existing := s.deviceByIP(e.IP)
	mdnsServices := []string{e.Service}
	if e.Instance != "" {
		mdnsServices = append(mdnsServices, e.Instance)
	}
	if existing != nil {
		mdnsServices = mergeStringSlices(existing.ProtocolsSeen.MDNS, mdnsServices)
	}
	vendor := ""
	mac := ""
	id := "ip_" + e.IP
	macIsLocallyAdmin := oui.IsLocallyAdministeredMAC(mac)
	if existing != nil {
		vendor = existing.Vendor
		mac = existing.MAC
		id = existing.ID
		macIsLocallyAdmin = existing.MACIsLocallyAdmin
	}
	hostname := e.Hostname
	if hostname == "" && existing != nil && existing.Hostname != nil {
		hostname = *existing.Hostname
	}
	now := time.Now().UTC().Format(time.RFC3339)
	sources := []string{"mdns"}
	if existing != nil {
		sources = mergeStringSlices(existing.SourcesSeen, sources)
	}
	d := store.Device{
		ID:                id,
		IP:                e.IP,
		MAC:               mac,
		Vendor:            vendor,
		Hostname:          strPtr(hostname),
		MACIsLocallyAdmin: macIsLocallyAdmin,
		ProtocolsSeen:     store.ProtocolsSeen{MDNS: mdnsServices, SSDP: nil, NetBIOS: nil},
		FirstSeen:         now,
		LastSeen:          now,
		Flags:             []string{},
		SourcesSeen:       sources,
	}
	if existing != nil {
		d.FirstSeen = existing.FirstSeen
		d.ProtocolsSeen.SSDP = existing.ProtocolsSeen.SSDP
		d.ProtocolsSeen.NetBIOS = existing.ProtocolsSeen.NetBIOS
		d.PortsOpen = existing.PortsOpen
		if existing.MACIsLocallyAdmin {
			d.MACIsLocallyAdmin = true
		}
		d.HTTPServer = existing.HTTPServer
		d.SSDPServer = existing.SSDPServer
		d.TLSSubject = existing.TLSSubject
		d.TLSIssuer = existing.TLSIssuer
		d.TLSSANS = existing.TLSSANS
		d.SSHBanner = existing.SSHBanner
	}
	d = s.recomputeClassification(d)
	s.store.AddOrUpdateDevice(s.scanID, d)
}

func (s *Scanner) upsertDeviceFromSSDP(e ssdp.Entry, desc *ssdp.DeviceDescription) {
	if !s.shouldTrackIP(e.IP) {
		return
	}
	existing := s.deviceByIP(e.IP)
	var ssdpServices []string
	if e.ST != "" {
		ssdpServices = append(ssdpServices, e.ST)
	}
	if e.USN != "" {
		ssdpServices = append(ssdpServices, e.USN)
	}
	if existing != nil {
		ssdpServices = mergeStringSlices(existing.ProtocolsSeen.SSDP, ssdpServices)
	}
	vendor := ""
	mac := ""
	id := "ip_" + e.IP
	hostname := ""
	macIsLocallyAdmin := oui.IsLocallyAdministeredMAC(mac)
	ssdpServer := e.Server
	if existing != nil {
		vendor = existing.Vendor
		mac = existing.MAC
		id = existing.ID
		if existing.Hostname != nil {
			hostname = *existing.Hostname
		}
		macIsLocallyAdmin = existing.MACIsLocallyAdmin
		if existing.SSDPServer != "" && ssdpServer == "" {
			ssdpServer = existing.SSDPServer
		}
	}
	// Enrich from SSDP device description XML (manufacturer, model, friendlyName)
	if desc != nil {
		if desc.Manufacturer != "" && vendor == "" {
			vendor = desc.Manufacturer
		}
		if desc.FriendlyName != "" && hostname == "" {
			hostname = desc.FriendlyName
		}
		if desc.ModelName != "" && vendor != "" {
			vendor = vendor + " " + desc.ModelName
		} else if desc.ModelName != "" {
			vendor = desc.ModelName
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	sources := []string{"ssdp"}
	if existing != nil {
		sources = mergeStringSlices(existing.SourcesSeen, sources)
	}
	d := store.Device{
		ID:                id,
		IP:                e.IP,
		MAC:               mac,
		Vendor:            vendor,
		MACIsLocallyAdmin: macIsLocallyAdmin,
		Hostname:          strPtr(hostname),
		SSDPServer:        ssdpServer,
		ProtocolsSeen:     store.ProtocolsSeen{MDNS: nil, SSDP: ssdpServices, NetBIOS: nil},
		FirstSeen:         now,
		LastSeen:          now,
		Flags:             []string{},
		SourcesSeen:       sources,
	}
	if existing != nil {
		d.FirstSeen = existing.FirstSeen
		d.ProtocolsSeen.MDNS = existing.ProtocolsSeen.MDNS
		d.ProtocolsSeen.NetBIOS = existing.ProtocolsSeen.NetBIOS
		d.PortsOpen = existing.PortsOpen
		if existing.MACIsLocallyAdmin {
			d.MACIsLocallyAdmin = true
		}
		d.HTTPServer = existing.HTTPServer
		d.TLSSubject = existing.TLSSubject
		d.TLSIssuer = existing.TLSIssuer
		d.TLSSANS = existing.TLSSANS
		d.SSHBanner = existing.SSHBanner
	}
	d = s.recomputeClassification(d)
	s.store.AddOrUpdateDevice(s.scanID, d)
}

func mergeIntSlices(a, b []int) []int {
	seen := make(map[int]struct{})
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		seen[v] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	return out
}

func (s *Scanner) shouldTrackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	ipv4 := parsed.To4()
	if ipv4 == nil || ipv4.IsLoopback() || ipv4.IsUnspecified() || ipv4.IsMulticast() || ipv4.IsLinkLocalMulticast() || ipv4.IsLinkLocalUnicast() {
		return false
	}
	if s.netInfo == nil || s.netInfo.Subnet == "" {
		return true
	}
	_, subnet, err := net.ParseCIDR(s.netInfo.Subnet)
	if err != nil {
		return true
	}
	return subnet.Contains(ipv4)
}

func mergeStringSlices(a, b []string) []string {
	m := make(map[string]struct{})
	for _, s := range a {
		m[s] = struct{}{}
	}
	for _, s := range b {
		m[s] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	return out
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func reverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

func containsAny(s string, subs ...string) bool {
	lower := strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(lower, strings.ToLower(x)) {
			return true
		}
	}
	return false
}

func containsInt(values []int, target int) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
