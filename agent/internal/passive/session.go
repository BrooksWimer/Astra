package passive

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func Start(cfg RuntimeConfig) *Session {
	cfg = normalizeConfig(cfg)
	s := &Session{
		done: make(chan struct{}),
		corpus: Corpus{
			CapturePoint:       "host_passive",
			Interface:          cfg.Interface,
			Window:             cfg.Window,
			StartedAt:          time.Now().UTC(),
			HostCaptureEnabled: cfg.Enabled,
			InfraEnabled:       cfg.InfraEnabled,
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
		go s.listenSyslog(ctx, cfg.SyslogListenAddr)
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
		s.loadResolverEvents(cfg.ResolverLogPath)
		s.loadDHCPLogEvents(cfg.DHCPLogPath)
		s.loadSessionProfileSource(cfg.SessionSource, cfg.SessionCommand)
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
	return cfg
}

func (s *Session) capturePackets(ctx context.Context, cfg RuntimeConfig) error {
	if strings.TrimSpace(cfg.Interface) == "" || strings.EqualFold(cfg.Interface, "primary") {
		return fmt.Errorf("passive_capture_interface_not_resolved")
	}
	inactive, err := pcap.NewInactiveHandle(cfg.Interface)
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
	s.corpus.CapturePoint = "pcap:" + cfg.Interface
	s.mu.Unlock()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		<-ctx.Done()
		handle.Close()
	}()
	for packet := range packetSource.Packets() {
		s.parsePacket(packet)
	}
	return nil
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
