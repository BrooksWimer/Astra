package passive

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func Start(cfg RuntimeConfig) *Session {
	cfg = normalizeConfig(cfg)
	s := &Session{
		done: make(chan struct{}),
		corpus: Corpus{
			CapturePoint:       "host_passive",
			Interface:          cfg.Interface,
			Window:             cfg.Window,
			InfraLookback:      cfg.InfraLookback,
			StartedAt:          time.Now().UTC(),
			HostCaptureEnabled: cfg.Enabled,
			InfraEnabled:       cfg.InfraEnabled,
			PCAPOutputPath:     strings.TrimSpace(cfg.PCAPOutputPath),
		},
	}
	go s.run(cfg)
	return s
}

func (s *Session) Wait() Corpus {
	if s == nil {
		return Corpus{}
	}
	<-s.done
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.corpus
}

func (s *Session) run(cfg RuntimeConfig) {
	defer close(s.done)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Window)
	defer cancel()

	var captureErr error
	done := make(chan struct{})
	if cfg.Enabled {
		go func() {
			captureErr = s.capturePackets(ctx, cfg)
			close(done)
		}()
	} else {
		s.setCaptureUnavailable("passive_capture_disabled")
		close(done)
	}

	if cfg.Enabled || cfg.InfraEnabled {
		go s.captureNetflow(ctx)
	}
	if cfg.InfraEnabled && strings.TrimSpace(cfg.SyslogListenAddr) != "" {
		go s.listenSyslog(ctx, cfg.SyslogListenAddr, cfg.WiFiFormat, cfg.RadiusFormat)
	}

	<-ctx.Done()
	<-done
	if cfg.Enabled {
		if captureErr != nil {
			s.setCaptureUnavailable(captureErr.Error())
		} else {
			s.setCaptureAvailable()
		}
	}
	if cfg.InfraEnabled {
		s.loadResolverEvents(cfg.ResolverLogPath, cfg.ResolverFormat, cfg.InfraLookback)
		s.loadDHCPLogEvents(cfg.DHCPLogPath, cfg.InfraLookback)
		s.loadSessionProfileSource(cfg.SessionSource, cfg.SessionCommand, cfg.SessionFormat, cfg.RadiusFormat, cfg.InfraLookback)
	}

	s.mu.Lock()
	s.corpus.FinishedAt = time.Now().UTC()
	s.mu.Unlock()
}

func normalizeConfig(cfg RuntimeConfig) RuntimeConfig {
	if cfg.Window <= 0 {
		cfg.Window = 120 * time.Second
	}
	if cfg.Interface == "" {
		cfg.Interface = "primary"
	}
	if cfg.Snaplen <= 0 {
		cfg.Snaplen = 262144
	}
	if cfg.BufferPackets <= 0 {
		cfg.BufferPackets = 4096
	}
	if cfg.InfraLookback <= 0 {
		cfg.InfraLookback = 15 * time.Minute
	}
	cfg.ResolverFormat = normalizeFormat(cfg.ResolverFormat)
	cfg.SessionFormat = normalizeFormat(cfg.SessionFormat)
	cfg.WiFiFormat = normalizeFormat(cfg.WiFiFormat)
	cfg.RadiusFormat = normalizeFormat(cfg.RadiusFormat)
	cfg.PCAPOutputPath = strings.TrimSpace(cfg.PCAPOutputPath)
	return cfg
}

func (s *Session) capturePackets(ctx context.Context, cfg RuntimeConfig) error {
	deviceName, err := resolveCaptureDevice(cfg)
	if err != nil {
		return err
	}
	inactive, err := pcap.NewInactiveHandle(deviceName)
	if err != nil {
		return err
	}
	defer inactive.CleanUp()
	_ = inactive.SetSnapLen(cfg.Snaplen)
	_ = inactive.SetPromisc(cfg.Promiscuous)
	_ = inactive.SetTimeout(500 * time.Millisecond)
	_ = inactive.SetBufferSize(cfg.BufferPackets * 256)
	handle, err := inactive.Activate()
	if err != nil {
		return err
	}
	defer handle.Close()
	_ = handle.SetBPFFilter("udp or tcp or icmp6")
	s.mu.Lock()
	s.corpus.Interface = deviceName
	s.corpus.CapturePoint = "pcap:" + deviceName
	s.mu.Unlock()
	pcapFile, pcapWriter := s.openPCAPWriter(cfg, handle)
	if pcapFile != nil {
		defer pcapFile.Close()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		<-ctx.Done()
		handle.Close()
	}()
	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			_ = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
		s.parsePacket(packet)
	}
	return nil
}

func normalizeFormat(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "auto"
	}
	return v
}

func (s *Session) openPCAPWriter(cfg RuntimeConfig, handle *pcap.Handle) (*os.File, *pcapgo.Writer) {
	path := strings.TrimSpace(cfg.PCAPOutputPath)
	if path == "" {
		return nil, nil
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			s.setPCAPError(err.Error())
			return nil, nil
		}
	}
	file, err := os.Create(path)
	if err != nil {
		s.setPCAPError(err.Error())
		return nil, nil
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(uint32(cfg.Snaplen), handle.LinkType()); err != nil {
		file.Close()
		s.setPCAPError(err.Error())
		return nil, nil
	}
	s.setPCAPOutputPath(path)
	return file, writer
}

func resolveCaptureDevice(cfg RuntimeConfig) (string, error) {
	desired := strings.TrimSpace(cfg.Interface)
	localIP := strings.TrimSpace(cfg.LocalIP)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	if len(devices) == 0 {
		return "", fmt.Errorf("no_pcap_devices_found")
	}
	if desired != "" && !strings.EqualFold(desired, "primary") {
		if match := matchCaptureDeviceByName(devices, desired); match != "" {
			return match, nil
		}
	}
	if localIP != "" {
		if match := matchCaptureDeviceByLocalIP(devices, localIP); match != "" {
			return match, nil
		}
	}
	if desired != "" && !strings.EqualFold(desired, "primary") {
		return "", fmt.Errorf("passive_capture_interface_not_found:%s", desired)
	}
	if match := firstUsableCaptureDevice(devices); match != "" {
		return match, nil
	}
	return "", fmt.Errorf("passive_capture_interface_not_resolved")
}

func matchCaptureDeviceByName(devices []pcap.Interface, desired string) string {
	want := strings.ToLower(strings.TrimSpace(desired))
	if want == "" {
		return ""
	}
	for _, dev := range devices {
		if strings.EqualFold(strings.TrimSpace(dev.Name), desired) {
			return dev.Name
		}
	}
	for _, dev := range devices {
		if strings.EqualFold(strings.TrimSpace(dev.Description), desired) {
			return dev.Name
		}
	}
	for _, dev := range devices {
		name := strings.ToLower(strings.TrimSpace(dev.Name))
		desc := strings.ToLower(strings.TrimSpace(dev.Description))
		if strings.Contains(name, want) || strings.Contains(desc, want) {
			return dev.Name
		}
	}
	return ""
}

func matchCaptureDeviceByLocalIP(devices []pcap.Interface, localIP string) string {
	ip := net.ParseIP(strings.TrimSpace(localIP))
	if ip == nil {
		return ""
	}
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if addr.IP != nil && addr.IP.Equal(ip) {
				return dev.Name
			}
		}
	}
	return ""
}

func firstUsableCaptureDevice(devices []pcap.Interface) string {
	for _, dev := range devices {
		if hasNonLoopbackAddress(dev) {
			return dev.Name
		}
	}
	if len(devices) == 0 {
		return ""
	}
	return devices[0].Name
}

func hasNonLoopbackAddress(dev pcap.Interface) bool {
	for _, addr := range dev.Addresses {
		if addr.IP == nil {
			continue
		}
		if addr.IP.IsLoopback() {
			continue
		}
		return true
	}
	return false
}

func (s *Session) setCaptureAvailable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.corpus.HostCaptureAvailable = true
	if s.corpus.CapturePoint == "" {
		s.corpus.CapturePoint = "pcap"
	}
}

func (s *Session) setCaptureUnavailable(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.corpus.HostCaptureAvailable = false
	if strings.TrimSpace(reason) == "" {
		reason = "passive_capture_unavailable"
	}
	s.corpus.HostCaptureReason = reason
}

func (s *Session) setPCAPOutputPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.corpus.PCAPOutputPath = strings.TrimSpace(path)
}

func (s *Session) setPCAPError(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.corpus.PCAPOutputError = strings.TrimSpace(reason)
}

func (s *Session) appendFlow(v FlowEvent) {
	s.mu.Lock()
	s.corpus.Flows = append(s.corpus.Flows, v)
	s.mu.Unlock()
}

func (s *Session) appendTLSServer(v TLSServerEvent) {
	s.mu.Lock()
	s.corpus.TLSServers = append(s.corpus.TLSServers, v)
	s.mu.Unlock()
}

func (s *Session) appendTLSClient(v TLSClientEvent) {
	s.mu.Lock()
	s.corpus.TLSClients = append(s.corpus.TLSClients, v)
	s.mu.Unlock()
}

func (s *Session) appendHTTP(v HTTPEvent) {
	s.mu.Lock()
	s.corpus.HTTP = append(s.corpus.HTTP, v)
	s.mu.Unlock()
}

func (s *Session) appendSSH(v SSHEvent) {
	s.mu.Lock()
	s.corpus.SSH = append(s.corpus.SSH, v)
	s.mu.Unlock()
}

func (s *Session) appendDHCP(v DHCPEvent) {
	s.mu.Lock()
	s.corpus.DHCP = append(s.corpus.DHCP, v)
	s.mu.Unlock()
}

func (s *Session) appendDNS(v DNSEvent) {
	s.mu.Lock()
	s.corpus.DNS = append(s.corpus.DNS, v)
	s.mu.Unlock()
}

func (s *Session) appendQUIC(v QUICEvent) {
	s.mu.Lock()
	s.corpus.QUIC = append(s.corpus.QUIC, v)
	s.mu.Unlock()
}

func (s *Session) appendIPv6(v IPv6Event) {
	s.mu.Lock()
	s.corpus.IPv6 = append(s.corpus.IPv6, v)
	s.mu.Unlock()
}

func (s *Session) appendMDNS(v MDNSEvent) {
	s.mu.Lock()
	s.corpus.MDNS = append(s.corpus.MDNS, v)
	s.mu.Unlock()
}

func (s *Session) appendSSDP(v SSDPEVent) {
	s.mu.Lock()
	s.corpus.SSDP = append(s.corpus.SSDP, v)
	s.mu.Unlock()
}

func (s *Session) appendNetflow(v NetflowEvent) {
	s.mu.Lock()
	s.corpus.Netflow = append(s.corpus.Netflow, v)
	s.mu.Unlock()
}

func (s *Session) appendWiFi(v WiFiEvent) {
	s.mu.Lock()
	s.corpus.WiFi = append(s.corpus.WiFi, v)
	s.mu.Unlock()
}

func (s *Session) appendResolver(v ResolverEvent) {
	s.mu.Lock()
	s.corpus.Resolver = append(s.corpus.Resolver, v)
	s.mu.Unlock()
}

func (s *Session) appendSessionProfile(v SessionProfileEvent) {
	s.mu.Lock()
	s.corpus.Sessions = append(s.corpus.Sessions, v)
	s.mu.Unlock()
}

func (s *Session) appendRadius(v RadiusEvent) {
	s.mu.Lock()
	s.corpus.Radius = append(s.corpus.Radius, v)
	s.mu.Unlock()
}
