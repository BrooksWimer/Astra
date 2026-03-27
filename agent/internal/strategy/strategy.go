package strategy

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/mdns"
	"github.com/netwise/agent/internal/oui"
	"github.com/netwise/agent/internal/passive"
	"github.com/netwise/agent/internal/ssdp"
)

const strategyProbeTimeout = 900 * time.Millisecond
const strategyCommandTimeout = 1800 * time.Millisecond

var (
	mdnsOnce              sync.Once
	ssdpOnce              sync.Once
	cachedMdns            []mdns.Entry
	cachedSsdp            []ssdp.Entry
	ssdpDescCache         sync.Map
	passiveRuntimeMu      sync.RWMutex
	passiveRuntimeSession *passive.Session
	passiveRuntimeCorpus  *passive.Corpus
)

var netbiosNameRegex = regexp.MustCompile(`(?i)^([A-Z0-9._-]{1,15})\s+<\d{2}>\s+(UNIQUE|GROUP)`)
var ipv4Regex = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|1?\d?\d)(?:\.(?:25[0-5]|2[0-4][0-9]|1?\d?\d)){3}\b`)
var ttlRegex = regexp.MustCompile(`(?i)ttl[=:]([0-9]+)`)
var macAddressRegex = regexp.MustCompile(`(?i)\b([0-9A-F]{2}[:-]){5}([0-9A-F]{2})\b`)
var manualLabelOnce sync.Once

type Target struct {
	IP       string
	MAC      string
	Hostname string
	Tags     map[string]string
}

type Observation struct {
	Timestamp int64
	Strategy  string
	IP        string
	MAC       string
	Hostname  string
	Key       string
	Value     string
	Details   map[string]string
}

type ObservationSink func(Observation)

type Strategy interface {
	Name() string
	Collect(targets []Target, emit ObservationSink)
}

type passiveWindowStat struct {
	First time.Time
	Last  time.Time
	Count int
}

func (s *passiveWindowStat) Add(ts time.Time) {
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if s.Count == 0 || s.First.IsZero() || ts.Before(s.First) {
		s.First = ts
	}
	if s.Count == 0 || s.Last.IsZero() || ts.After(s.Last) {
		s.Last = ts
	}
	s.Count++
}

func StartPassiveRuntime(cfg *config.Config, localIP, ifaceName string) {
	if cfg == nil {
		cfg = config.Default()
	}
	interfaceName := strings.TrimSpace(cfg.PassiveCaptureInterface)
	if interfaceName == "" || strings.EqualFold(interfaceName, "primary") {
		interfaceName = strings.TrimSpace(ifaceName)
	}
	passiveRuntimeMu.Lock()
	defer passiveRuntimeMu.Unlock()
	passiveRuntimeCorpus = nil
	passiveRuntimeSession = passive.Start(passive.RuntimeConfig{
		Enabled:          cfg.PassiveCaptureEnabled,
		Window:           time.Duration(cfg.PassiveCaptureWindowSeconds) * time.Second,
		Interface:        interfaceName,
		Promiscuous:      cfg.PassiveCapturePromiscuous,
		Snaplen:          cfg.PassiveCaptureSnaplen,
		BufferPackets:    cfg.PassiveCaptureBufferPackets,
		LocalIP:          strings.TrimSpace(localIP),
		InfraEnabled:     cfg.PassiveInfraEnabled,
		InfraLookback:    time.Duration(cfg.PassiveInfraLookbackMinutes) * time.Minute,
		ResolverFormat:   strings.TrimSpace(cfg.PassiveResolverFormat),
		SessionFormat:    strings.TrimSpace(cfg.PassiveSessionFormat),
		WiFiFormat:       strings.TrimSpace(cfg.PassiveWiFiFormat),
		RadiusFormat:     strings.TrimSpace(cfg.PassiveRadiusFormat),
		SyslogListenAddr: strings.TrimSpace(cfg.PassiveSyslogListenAddr),
		ResolverLogPath:  strings.TrimSpace(cfg.PassiveResolverLogPath),
		DHCPLogPath:      strings.TrimSpace(cfg.PassiveDHCPLogPath),
		SessionSource:    strings.TrimSpace(cfg.PassiveSessionSource),
		SessionCommand:   strings.TrimSpace(cfg.PassiveSessionCommand),
		PCAPOutputPath:   strings.TrimSpace(cfg.PassivePCAPOutputPath),
	})
}

func StopPassiveRuntime() {
	passiveRuntimeMu.Lock()
	session := passiveRuntimeSession
	passiveRuntimeSession = nil
	passiveRuntimeMu.Unlock()
	if session == nil {
		return
	}
	corpus := session.Wait()
	passiveRuntimeMu.Lock()
	passiveRuntimeCorpus = &corpus
	passiveRuntimeMu.Unlock()
}

func passiveCorpus() passive.Corpus {
	passiveRuntimeMu.RLock()
	if passiveRuntimeCorpus != nil {
		corpus := *passiveRuntimeCorpus
		passiveRuntimeMu.RUnlock()
		return corpus
	}
	session := passiveRuntimeSession
	passiveRuntimeMu.RUnlock()
	if session == nil {
		return passive.Corpus{}
	}
	corpus := session.Wait()
	passiveRuntimeMu.Lock()
	passiveRuntimeCorpus = &corpus
	passiveRuntimeMu.Unlock()
	return corpus
}

func PassiveRuntimeSnapshot() passive.Corpus {
	return passiveCorpus()
}

func passiveObservationDetails(corpus passive.Corpus, matchQuality, sourceScope string, stat passiveWindowStat, extra map[string]string) map[string]string {
	details := map[string]string{
		"capture_point":      strings.TrimSpace(corpus.CapturePoint),
		"observation_window": corpus.Window.String(),
		"match_quality":      strings.TrimSpace(matchQuality),
		"source_scope":       strings.TrimSpace(sourceScope),
	}
	if !stat.First.IsZero() {
		details["first_observed"] = stat.First.UTC().Format(time.RFC3339)
	}
	if !stat.Last.IsZero() {
		details["last_observed"] = stat.Last.UTC().Format(time.RFC3339)
	}
	if stat.Count > 0 {
		details["hit_count"] = strconv.Itoa(stat.Count)
	}
	for k, v := range extra {
		v = strings.TrimSpace(v)
		if v != "" {
			details[k] = v
		}
	}
	return details
}

func passiveStatusDetails(corpus passive.Corpus, sourceScope, reason string, extra map[string]string) map[string]string {
	details := map[string]string{
		"capture_point":      strings.TrimSpace(corpus.CapturePoint),
		"observation_window": corpus.Window.String(),
		"source_scope":       strings.TrimSpace(sourceScope),
		"reason":             strings.TrimSpace(reason),
	}
	if details["capture_point"] == "" {
		details["capture_point"] = sourceScope
	}
	for k, v := range extra {
		v = strings.TrimSpace(v)
		if v != "" {
			details[k] = v
		}
	}
	return details
}

func passiveHostStatusReason(corpus passive.Corpus) string {
	switch {
	case !corpus.HostCaptureEnabled:
		return "passive_capture_disabled"
	case !corpus.HostCaptureAvailable:
		if strings.TrimSpace(corpus.HostCaptureReason) != "" {
			return strings.TrimSpace(corpus.HostCaptureReason)
		}
		return "passive_capture_unavailable"
	default:
		return ""
	}
}

func passiveMatchIdentity(t Target, ip, mac, hostname string) (string, bool) {
	targetIP := strings.TrimSpace(strings.ToLower(t.IP))
	candidateIP := strings.TrimSpace(strings.ToLower(ip))
	targetMAC := normalizeTargetMAC(t.MAC)
	candidateMAC := normalizeTargetMAC(mac)
	targetHost := normalizeTargetHost(t.Hostname)
	candidateHost := normalizeTargetHost(hostname)
	switch {
	case targetIP != "" && candidateIP != "" && targetIP == candidateIP:
		return "direct_match", true
	case targetMAC != "" && candidateMAC != "" && targetMAC == candidateMAC:
		return "direct_match", true
	case targetHost != "" && candidateHost != "" && targetHost == candidateHost:
		return "strong_inferred_match", true
	default:
		return "", false
	}
}

func passiveMatchFlowTarget(t Target, srcIP, dstIP, srcMAC, dstMAC string) (string, string, string, bool) {
	if quality, ok := passiveMatchIdentity(t, srcIP, srcMAC, ""); ok {
		return quality, "outbound", strings.TrimSpace(dstIP), true
	}
	if quality, ok := passiveMatchIdentity(t, dstIP, dstMAC, ""); ok {
		return quality, "inbound", strings.TrimSpace(srcIP), true
	}
	return "", "", "", false
}

func normalizeTargetMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	return strings.ReplaceAll(mac, "-", ":")
}

func normalizeTargetHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".local")
	host = strings.TrimSuffix(host, ".")
	return host
}

const (
	ObservationStatusRealData      = "real_data"
	ObservationStatusNoResponse    = "no_response"
	ObservationStatusUnsupported   = "unsupported"
	ObservationStatusNotApplicable = "not_applicable"
	ObservationStatusNotAvailable  = "not_available"
)

func nowMs() int64 {
	return time.Now().UnixMilli()
}

func nowUnix() string {
	return time.Now().Format(time.RFC3339)
}

func emitObservation(emit ObservationSink, strategyName string, t Target, key, value string, details map[string]string) {
	if emit == nil || t.IP == "" {
		return
	}
	emit(Observation{
		Timestamp: nowMs(),
		Strategy:  strategyName,
		IP:        t.IP,
		MAC:       t.MAC,
		Hostname:  t.Hostname,
		Key:       key,
		Value:     value,
		Details:   details,
	})
}

func collectL2NeighborDiscovery(strategyName string, targets []Target, emit ObservationSink) {
	outputs := collectL2NeighborOutputs()
	if len(outputs) == 0 {
		for _, t := range targets {
			collectL2NeighborFallback(strategyName, t, emit)
		}
		return
	}

	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		seen := map[string]struct{}{}
		needles := []string{strings.ToLower(t.IP)}
		mac := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(t.MAC, ":", "-"), "-", ":"))
		if mac != "" {
			needles = append(needles, strings.ToLower(mac), strings.ToLower(strings.ReplaceAll(mac, "-", "")))
		}
		if t.Hostname != "" {
			needles = append(needles, strings.ToLower(t.Hostname), strings.ToLower(strings.TrimSuffix(t.Hostname, ".local")))
		}
		for _, output := range outputs {
			for _, line := range strings.Split(output, "\n") {
				l := strings.TrimSpace(line)
				if l == "" {
					continue
				}
				ll := strings.ToLower(l)
				for _, n := range needles {
					if n != "" && strings.Contains(ll, n) {
						seen[l] = struct{}{}
						break
					}
				}
			}
		}
		if len(seen) == 0 {
			emitObservation(emit, strategyName, t, "neighbor", "not_seen", map[string]string{"reason": "no_match"})
			continue
		}
		keys := make([]string, 0, len(seen))
		for k := range seen {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			emitObservation(emit, strategyName, t, "neighbor", k, nil)
		}
	}
}

func collectL2NeighborFallback(strategyName string, t Target, emit ObservationSink) {
	emitObservation(emit, strategyName, t, "neighbor", "not_available", map[string]string{"reason": "no_lldp_or_cdp_tools"})
}

func collectLLMNRResponder(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		name := strings.TrimSpace(t.Hostname)
		if name == "" {
			emitObservation(emit, strategyName, t, "llmnr", "no_hostname", nil)
			continue
		}
		found := false
		for _, ip := range queryLLMNRByName(name) {
			emitObservation(emit, strategyName, t, "llmnr_ip", ip, nil)
			found = true
		}
		if !found {
			emitObservation(emit, strategyName, t, "llmnr", "not_found", nil)
		}
	}
}

func collectPassiveServiceFingerprintPcap(strategyName string, targets []Target, emit ObservationSink) {
	ports := []int{21, 22, 23, 25, 80, 110, 139, 443, 445, 554, 631, 3389, 5060, 5900, 8000, 8080, 8443, 9000}
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		found := false
		for _, p := range ports {
			banner := readTCPServiceBanner(t.IP, p)
			if banner == "" {
				continue
			}
			found = true
			emitObservation(emit, strategyName, t, "service_banner", banner, map[string]string{"port": strconv.Itoa(p)})
		}
		if !found {
			emitObservation(emit, strategyName, t, "service_banner", "none", nil)
		}
	}
}

func collectPacketTTLOSFingerprint(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		ttl, source := collectTTLViaPing(t.IP)
		if ttl == 0 {
			emitObservation(emit, strategyName, t, "ttl", "not_observed", map[string]string{"source": source})
			continue
		}
		emitObservation(emit, strategyName, t, "ttl", strconv.Itoa(ttl), map[string]string{
			"source":  source,
			"os_hint": estimateOSFromTTL(ttl),
		})
	}
}

func collectWireless11Beacon(strategyName string, targets []Target, emit ObservationSink) {
	beacons := collectWirelessBeacons()
	for _, t := range targets {
		if len(beacons) == 0 {
			emitObservation(emit, strategyName, t, "wireless_beacons", "none", nil)
			continue
		}
		emitObservation(emit, strategyName, t, "wireless_beacons", beacons["summary"], map[string]string{"samples": beacons["samples"]})
	}
}

func collectManualOperatorLabelFallback(strategyName string, targets []Target, emit ObservationSink) {
	labels := manualOperatorLabels()
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		if v, ok := labels[strings.ToLower(strings.TrimSpace(t.IP))]; ok {
			emitObservation(emit, strategyName, t, "manual_label", v, nil)
			continue
		}
		if t.Hostname != "" {
			host := strings.ToLower(strings.TrimSpace(t.Hostname))
			if v, ok := labels[host]; ok {
				emitObservation(emit, strategyName, t, "manual_label", v, nil)
				continue
			}
			if v, ok := labels[strings.TrimSuffix(host, ".local")]; ok {
				emitObservation(emit, strategyName, t, "manual_label", v, nil)
				continue
			}
		}
		emitObservation(emit, strategyName, t, "manual_label", "unlabeled", map[string]string{"reason": "no_override"})
	}
}

func collectEvidenceGraphMerger(strategyName string, targets []Target, emit ObservationSink) {
	macIndex := map[string][]string{}
	hostIndex := map[string][]string{}
	for _, t := range targets {
		if t.MAC != "" {
			macKey := strings.ToLower(strings.ReplaceAll(t.MAC, "-", ":"))
			macIndex[macKey] = append(macIndex[macKey], t.IP)
		}
		if t.Hostname != "" {
			h := strings.ToLower(strings.TrimSpace(t.Hostname))
			hostIndex[h] = append(hostIndex[h], t.IP)
		}
	}
	for _, t := range targets {
		edges := []string{}
		if t.MAC != "" {
			key := strings.ToLower(strings.ReplaceAll(t.MAC, "-", ":"))
			for _, ip := range macIndex[key] {
				if ip != t.IP {
					edges = append(edges, "mac_peer:"+ip)
				}
			}
		}
		if t.Hostname != "" {
			key := strings.ToLower(strings.TrimSpace(t.Hostname))
			for _, ip := range hostIndex[key] {
				if ip != t.IP {
					edges = append(edges, "hostname_peer:"+ip)
				}
			}
		}
		if len(edges) == 0 {
			emitObservation(emit, strategyName, t, "evidence_graph", "orphan", nil)
			continue
		}
		sort.Strings(edges)
		for _, edge := range edges {
			emitObservation(emit, strategyName, t, "evidence_graph", edge, nil)
		}
	}
}

func collectHostEventLogPull(strategyName string, targets []Target, emit ObservationSink) {
	events := collectLocalHostEvents()
	if len(events) == 0 {
		for _, t := range targets {
			emitObservation(emit, strategyName, t, "host_event", "none", map[string]string{"source": "local_host"})
		}
		return
	}
	for _, t := range targets {
		for _, e := range events {
			emitObservation(emit, strategyName, t, "host_event", e, map[string]string{"source": "local_host"})
		}
	}
}

func collectIdentityTargets(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		emitObservation(emit, strategyName, t, "ip", t.IP, nil)
		emitObservation(emit, strategyName, t, "mac", t.MAC, nil)
		emitObservation(emit, strategyName, t, "hostname", t.Hostname, nil)
	}
}

func collectMacOUI(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		emitObservation(emit, strategyName, t, "vendor", oui.Lookup(t.MAC), map[string]string{"locally_admin": strconv.FormatBool(oui.IsLocallyAdministeredMAC(t.MAC))})
	}
}

func collectDHCPLeaseHints(strategyName string, targets []Target, emit ObservationSink) {
	paths := dhcpLeasePaths()
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		found := false
		mac := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(t.MAC), ":", ""), "-", "")
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			body := strings.ToLower(string(data))
			if strings.Contains(body, strings.ToLower(t.IP)) {
				emitObservation(emit, strategyName, t, "lease_match", "ip", map[string]string{"file": p})
				found = true
			}
			if mac != "" && strings.Contains(body, mac) {
				emitObservation(emit, strategyName, t, "lease_match", "mac", map[string]string{"file": p})
				found = true
			}
		}
		if !found {
			emitObservation(emit, strategyName, t, "lease_match", "not_found", nil)
		}
	}
	if len(paths) == 0 {
		for _, t := range targets {
			emitObservation(emit, strategyName, t, "dhcp_hint", "no_lease_files", nil)
		}
	}
}

func collectDNSReverse(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		names, err := net.LookupAddr(t.IP)
		if err != nil || len(names) == 0 {
			emitObservation(emit, strategyName, t, "ptr", "none", nil)
			continue
		}
		for _, n := range names {
			emitObservation(emit, strategyName, t, "ptr", strings.TrimSuffix(n, "."), nil)
		}
	}
}

func collectDNSQueries(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		h := strings.TrimSpace(t.Hostname)
		if h == "" {
			emitObservation(emit, strategyName, t, "dns_query", "no_hostname", nil)
			continue
		}
		ips, err := net.LookupIP(h)
		if err != nil || len(ips) == 0 {
			emitObservation(emit, strategyName, t, "dns_query", "lookup_error", nil)
			continue
		}
		for _, ip := range ips {
			emitObservation(emit, strategyName, t, "dns_query", ip.String(), nil)
		}
	}
}

func collectMDNSLegacy(strategyName string, targets []Target, emit ObservationSink) {
	entries := mdnsEntries()
	if len(entries) == 0 {
		for _, t := range targets {
			emitObservation(emit, strategyName, t, "mdns", "none", nil)
		}
		return
	}
	for _, t := range targets {
		seen := false
		for _, e := range entries {
			if e.IP != t.IP {
				continue
			}
			seen = true
			emitObservation(emit, strategyName, t, "mdns_service", e.Service, map[string]string{"instance": e.Instance, "hostname": e.Hostname})
		}
		if !seen {
			emitObservation(emit, strategyName, t, "mdns", "not_seen", nil)
		}
	}
}

func collectSSDPLegacy(strategyName string, targets []Target, emit ObservationSink) {
	entries := ssdpEntries()
	if len(entries) == 0 {
		for _, t := range targets {
			emitObservation(emit, strategyName, t, "ssdp", "none", nil)
		}
		return
	}
	for _, t := range targets {
		seen := false
		for _, e := range entries {
			if e.IP != t.IP {
				continue
			}
			seen = true
			emitObservation(emit, strategyName, t, "ssdp_st", e.ST, map[string]string{"usn": e.USN, "server": e.Server})
		}
		if !seen {
			emitObservation(emit, strategyName, t, "ssdp", "not_seen", nil)
		}
	}
}

func collectUPNPDescription(strategyName string, targets []Target, emit ObservationSink) {
	entries := ssdpEntries()
	for _, t := range targets {
		found := false
		for _, e := range entries {
			if e.IP != t.IP || e.Location == "" {
				continue
			}
			desc := fetchUPnPDescription(e.Location)
			if desc == nil {
				continue
			}
			if desc.Manufacturer != "" {
				emitObservation(emit, strategyName, t, "upnp_manufacturer", desc.Manufacturer, nil)
				found = true
			}
			if desc.ModelName != "" {
				emitObservation(emit, strategyName, t, "upnp_model", desc.ModelName, nil)
				found = true
			}
			if desc.FriendlyName != "" {
				emitObservation(emit, strategyName, t, "upnp_friendly", desc.FriendlyName, nil)
				found = true
			}
		}
		if !found {
			emitObservation(emit, strategyName, t, "upnp", "none", nil)
		}
	}
}

func collectNetBIOS(strategyName string, targets []Target, emit ObservationSink) {
	if runtime.GOOS != "windows" {
		for _, t := range targets {
			emitObservation(emit, strategyName, t, "netbios", "windows_only", nil)
		}
		return
	}
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		cmd := exec.Command("nbtstat", "-A", t.IP)
		out, err := cmd.CombinedOutput()
		if err != nil {
			emitObservation(emit, strategyName, t, "netbios", "lookup_error", nil)
			continue
		}
		names := parseNetBIOSNames(string(out))
		if len(names) == 0 {
			emitObservation(emit, strategyName, t, "netbios", "none", nil)
			continue
		}
		for _, n := range names {
			emitObservation(emit, strategyName, t, "netbios", n, nil)
		}
	}
}

func collectTLS(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		subject, issuer, sans := fetchTLSFingerprint(t.IP, 443)
		if subject == "" && issuer == "" && sans == "" {
			subject, issuer, sans = fetchTLSFingerprint(t.IP, 8443)
		}
		if subject == "" && issuer == "" && sans == "" {
			emitObservation(emit, strategyName, t, "tls", "no_data", nil)
			continue
		}
		emitObservation(emit, strategyName, t, "tls_subject", subject, nil)
		emitObservation(emit, strategyName, t, "tls_issuer", issuer, nil)
		emitObservation(emit, strategyName, t, "tls_sans", sans, nil)
	}
}

func collectSSHBanner(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		banner := fetchSSHBanner(t.IP)
		if banner == "" {
			emitObservation(emit, strategyName, t, "ssh_banner", "none", nil)
			continue
		}
		emitObservation(emit, strategyName, t, "ssh_banner", banner, nil)
	}
}

func collectHTTPMetadata(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		headers := probeHTTPHeaders(t.IP)
		if len(headers) == 0 {
			emitObservation(emit, strategyName, t, "http", "no_response", nil)
			continue
		}
		for key, value := range headers {
			emitObservation(emit, strategyName, t, "http_"+key, value, nil)
		}
	}
}

func collectFavicon(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		result := probeFavicon(t.IP)
		if result.hash == "" {
			emitObservation(emit, strategyName, t, "favicon", "none", nil)
			continue
		}
		emitObservation(emit, strategyName, t, "favicon_sha1", result.hash, map[string]string{"size": strconv.Itoa(result.size)})
	}
}

func collectReachability(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		open := 0
		for _, p := range []int{22, 80, 443} {
			if isTCPPortOpen(t.IP, p, strategyProbeTimeout) {
				open++
			}
		}
		if open > 0 {
			emitObservation(emit, strategyName, t, "icmp_like", "reachable", map[string]string{"open_ports": strconv.Itoa(open)})
		} else {
			emitObservation(emit, strategyName, t, "icmp_like", "no_tcp_probe", nil)
		}
	}
}

func collectPortSet(strategyName string, targets []Target, emit ObservationSink, ports []int) {
	for _, t := range targets {
		openPorts := []string{}
		for _, p := range ports {
			if isTCPPortOpen(t.IP, p, strategyProbeTimeout) {
				openPorts = append(openPorts, strconv.Itoa(p))
			}
		}
		if len(openPorts) == 0 {
			emitObservation(emit, strategyName, t, "ports", "none", nil)
			continue
		}
		sort.Strings(openPorts)
		emitObservation(emit, strategyName, t, "ports", strings.Join(openPorts, ","), nil)
	}
}

func collectSMB(strategyName string, targets []Target, emit ObservationSink) {
	if strategyName == "smb_nbns_active" {
		collectUDPCheck(strategyName, targets, emit, "udp", 137)
		return
	}
	collectPortSet(strategyName, targets, emit, []int{139, 445})
}

func collectSNMP(strategyName string, targets []Target, emit ObservationSink, port int) {
	collectUDPCheck(strategyName, targets, emit, "udp", port)
}

func collectHTTPAPI(strategyName string, targets []Target, emit ObservationSink) {
	paths := []string{"/", "/api", "/api/status", "/api/v1", "/api/info", "/api/system", "/status", "/health"}
	for _, t := range targets {
		seen := false
		for _, p := range paths {
			res := probeHTTPPath(t.IP, p)
			if res.status == 0 {
				continue
			}
			seen = true
			emitObservation(emit, strategyName, t, "http_api", p, map[string]string{"status": strconv.Itoa(res.status), "content_type": res.contentType})
		}
		if !seen {
			emitObservation(emit, strategyName, t, "http_api", "none", nil)
		}
	}
}

func collectGatewayLookup(strategyName string, targets []Target, emit ObservationSink) {
	gateway := ""
	for _, t := range targets {
		if v, ok := t.Tags["gateway"]; ok {
			gateway = v
			break
		}
	}
	for _, t := range targets {
		if t.IP == gateway {
			emitObservation(emit, strategyName, t, "gateway", "match", nil)
		} else {
			emitObservation(emit, strategyName, t, "gateway", "no_match", map[string]string{"known_gateway": gateway})
		}
	}
}

func collectIPv6ULA(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		ip := strings.TrimSpace(t.IP)
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To16() == nil || parsed.To4() != nil {
			emitObservation(emit, strategyName, t, "ipv6_ula", "not_ipv6", nil)
			continue
		}
		parsed = parsed.To16()
		if parsed[0] == 0xfc || parsed[0] == 0xfd {
			emitObservation(emit, strategyName, t, "ipv6_ula", "true", nil)
		} else {
			emitObservation(emit, strategyName, t, "ipv6_ula", "false", nil)
		}
	}
}

func collectCorrelationStamp(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		emitObservation(emit, strategyName, t, "scan_time", nowUnix(), map[string]string{"batch": strconv.Itoa(len(targets))})
	}
}

func collectDirectory(strategyName string, targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.Hostname == "" || !strings.Contains(t.Hostname, ".") {
			emitObservation(emit, strategyName, t, "domain", "n/a", nil)
			continue
		}
		parts := strings.SplitN(t.Hostname, ".", 2)
		if len(parts) == 2 {
			emitObservation(emit, strategyName, t, "domain", parts[1], nil)
		}
	}
}

func collectL2NeighborOutputs() []string {
	commands := [][]string{
		{"lldpd", "-v"},
		{"lldpcli", "show", "neighbors"},
		{"lldpcli", "show", "neighbors", "details"},
		{"lldpctl"},
		{"cdpr", "show", "neighbors"},
	}
	if runtime.GOOS == "windows" {
		commands = [][]string{
			{"powershell", "-NoProfile", "-Command", "Get-CimInstance -Namespace root\\wmi -Class MSNdis_NetLldp -ErrorAction SilentlyContinue | Format-List -Property *"},
			{"powershell", "-NoProfile", "-Command", "Get-NetLldpAgent -ErrorAction SilentlyContinue | Format-List -Property *"},
		}
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, c := range commands {
		o, err := runCommandOutput(c...)
		if err != nil || len(strings.TrimSpace(o)) == 0 {
			continue
		}
		o = strings.TrimSpace(o)
		if _, ok := seen[o]; ok {
			continue
		}
		seen[o] = struct{}{}
		out = append(out, o)
	}
	return out
}

func runCommandOutput(cmdParts ...string) (string, error) {
	if len(cmdParts) == 0 {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), strategyCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdParts[0], cmdParts[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", err
	}
	return string(out), nil
}

func queryLLMNRByName(hostname string) []string {
	name := strings.TrimSpace(hostname)
	if name == "" {
		return nil
	}
	candidates := [][]string{
		{"powershell", "-NoProfile", "-Command", "Resolve-DnsName -Name '" + sanitizeShellValue(name) + "' -Type A -LlmnrOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress"},
		{"avahi-resolve-host-name", name + ".local"},
		{"dns-sd", "-G", "v4", name + ".local"},
	}
	var out []string
	seen := map[string]struct{}{}
	for _, c := range candidates {
		text, err := runCommandOutput(c...)
		if err != nil {
			continue
		}
		for _, ip := range parseIPv4FromText(text) {
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	return out
}

func collectTTLViaPing(ip string) (int, string) {
	var cmd []string
	source := "ping"
	if runtime.GOOS == "windows" {
		cmd = []string{"ping", "-n", "1", "-w", "900", ip}
	} else if runtime.GOOS == "darwin" {
		cmd = []string{"ping", "-c", "1", "-W", "1", ip}
	} else {
		cmd = []string{"ping", "-c", "1", "-W", "1", ip}
	}
	out, err := runCommandOutput(cmd...)
	if err != nil {
		source = "ping_exec_error"
	}
	m := ttlRegex.FindStringSubmatch(out)
	if len(m) < 2 {
		return 0, source
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, source
	}
	return v, source
}

func estimateOSFromTTL(ttl int) string {
	switch {
	case ttl <= 64:
		return "unix_like"
	case ttl <= 128:
		return "windows_like"
	case ttl <= 255:
		return "network_device"
	default:
		return "unknown"
	}
}

func collectWirelessBeacons() map[string]string {
	commands := [][]string{
		{"netsh", "wlan", "show", "networks", "mode=Bssid"},
		{"nmcli", "-t", "-f", "IN-USE,SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi"},
		{"airport", "-s"},
		{"system_profiler", "SPAirPortDataType"},
	}
	macSeen := map[string]struct{}{}
	ssids := map[string]struct{}{}
	for _, c := range commands {
		out, err := runCommandOutput(c...)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			for _, m := range macAddressRegex.FindAllString(line, -1) {
				macSeen[strings.ToLower(m)] = struct{}{}
			}
			if fields := strings.Fields(line); len(fields) > 0 {
				if len(fields[0]) > 1 && !strings.Contains(fields[0], ":") && !strings.Contains(fields[0], ".") {
					ssids[fields[0]] = struct{}{}
				}
			}
		}
	}
	if len(macSeen) == 0 && len(ssids) == 0 {
		return map[string]string{}
	}
	macList := dedupeMapKeys(macSeen)
	ssidList := dedupeMapKeys(ssids)
	samples := append(ssidList, macList...)
	sort.Strings(samples)
	if len(samples) > 8 {
		samples = samples[:8]
	}
	return map[string]string{
		"summary": strconv.Itoa(len(macList)),
		"samples": strings.Join(samples, ";"),
	}
}

func manualOperatorLabels() map[string]string {
	labels := map[string]string{}
	manualLabelOnce.Do(func() {
		paths := []string{
			"./manual_labels.json",
			"./operator_labels.json",
			"./labels.json",
			filepath.Join(os.Getenv("APPDATA"), "netwise", "manual_labels.json"),
			filepath.Join(os.Getenv("USERPROFILE"), "netwise", "manual_labels.json"),
			"/etc/netwise/manual_labels.json",
			"/etc/netwise/operator_labels.json",
			"/etc/netwise/labels.json",
			"/var/lib/netwise/manual_labels.json",
		}
		for _, p := range paths {
			if p == "" {
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			m := map[string]string{}
			if err := json.Unmarshal(data, &m); err == nil {
				for k, v := range m {
					k = strings.ToLower(strings.TrimSpace(k))
					v = strings.TrimSpace(v)
					if k != "" && v != "" {
						labels[k] = v
					}
				}
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				k := strings.ToLower(strings.TrimSpace(parts[0]))
				v := strings.TrimSpace(parts[1])
				if k != "" && v != "" {
					labels[k] = v
				}
			}
		}
	})
	return labels
}

func collectLocalHostEvents() []string {
	cmds := [][]string{}
	switch runtime.GOOS {
	case "windows":
		cmds = [][]string{
			{"powershell", "-NoProfile", "-Command", "Get-EventLog -LogName System -Newest 5 | Select-Object -ExpandProperty Message"},
			{"wevtutil", "qe", "System", "/c:5", "/f:Text"},
		}
	case "darwin":
		cmds = [][]string{
			{"log", "show", "--last", "5m", "--style", "syslog"},
		}
	default:
		cmds = [][]string{
			{"journalctl", "-p", "warning", "-n", "10", "--no-pager"},
			{"tail", "-n", "20", "/var/log/syslog"},
			{"tail", "-n", "20", "/var/log/messages"},
		}
	}
	for _, c := range cmds {
		out, err := runCommandOutput(c...)
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		lines := dedupeStrings(strings.Split(strings.TrimSpace(out), "\n"))
		if len(lines) == 0 {
			continue
		}
		if len(lines) > 12 {
			lines = lines[:12]
		}
		outLines := make([]string, 0, len(lines))
		for _, line := range lines {
			l := strings.TrimSpace(line)
			if l != "" {
				outLines = append(outLines, l)
			}
		}
		if len(outLines) > 0 {
			return outLines
		}
	}
	return nil
}

func readTCPServiceBanner(ip string, port int) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), strategyProbeTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(strategyProbeTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(strategyProbeTimeout))
	switch port {
	case 22, 21, 23:
		_, _ = conn.Write([]byte(""))
	case 80, 8080, 8443:
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n"))
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return ""
	}
	raw := normalizeBanner(string(buf[:n]))
	if raw == "" {
		return ""
	}
	sum := sha1.Sum([]byte(raw))
	if len(raw) > 180 {
		raw = raw[:180]
	}
	return "tcp://" + net.JoinHostPort(ip, strconv.Itoa(port)) + ":" + raw + ":" + hex.EncodeToString(sum[:])
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeBanner(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func parseIPv4FromText(text string) []string {
	matches := ipv4Regex.FindAllString(text, -1)
	return dedupeStrings(matches)
}

func dedupeMapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sanitizeShellValue(v string) string {
	return strings.ReplaceAll(v, "'", "''")
}

func collectNotAvailable(strategyName string, targets []Target, emit ObservationSink, reason string) {
	for _, t := range targets {
		emitObservation(emit, strategyName, t, "status", ObservationStatusNotAvailable, map[string]string{"reason": reason})
	}
}

func collectUDPCheck(strategyName string, targets []Target, emit ObservationSink, network string, port int) {
	for _, t := range targets {
		status := ObservationStatusNoResponse
		details := map[string]string{
			"transport": network,
			"port":      strconv.Itoa(port),
			"method":    "generic_udp_probe",
		}
		if isUDPPortOpen(t.IP, port, strategyProbeTimeout) {
			status = ObservationStatusRealData
			details["response_observed"] = "true"
		} else {
			details["response_observed"] = "false"
		}
		emitObservation(emit, strategyName, t, network+"_"+strconv.Itoa(port), status, details)
	}
}

func mdnsEntries() []mdns.Entry {
	if len(cachedMdns) > 0 {
		out := make([]mdns.Entry, len(cachedMdns))
		copy(out, cachedMdns)
		return out
	}
	mdnsOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cachedMdns = mdns.Browse(ctx, nil, nil, 2*time.Second)
	})
	out := make([]mdns.Entry, len(cachedMdns))
	copy(out, cachedMdns)
	return out
}

func ssdpEntries() []ssdp.Entry {
	if len(cachedSsdp) > 0 {
		out := make([]ssdp.Entry, len(cachedSsdp))
		copy(out, cachedSsdp)
		return out
	}
	ssdpOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cachedSsdp = ssdp.Discover(ctx, "", 3*time.Second)
	})
	out := make([]ssdp.Entry, len(cachedSsdp))
	copy(out, cachedSsdp)
	return out
}

func SeedMDNSCache(entries []mdns.Entry) {
	if len(entries) == 0 {
		return
	}
	cachedMdns = make([]mdns.Entry, len(entries))
	copy(cachedMdns, entries)
}

func SeedSSDPCache(entries []ssdp.Entry) {
	if len(entries) == 0 {
		return
	}
	cachedSsdp = make([]ssdp.Entry, len(entries))
	copy(cachedSsdp, entries)
}

func fetchUPnPDescription(location string) *ssdp.DeviceDescription {
	if location == "" {
		return nil
	}
	if d, ok := ssdpDescCache.Load(location); ok {
		if desc, ok2 := d.(*ssdp.DeviceDescription); ok2 {
			return desc
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	d := ssdp.FetchDeviceDescription(ctx, location, 4*time.Second)
	if d == nil {
		return nil
	}
	ssdpDescCache.Store(location, d)
	return d
}

func parseNetBIOSNames(output string) []string {
	sc := bufio.NewScanner(strings.NewReader(output))
	seen := make(map[string]struct{})
	names := []string{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m := netbiosNameRegex.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		name := strings.TrimSpace(m[1])
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

func isTCPPortOpen(ip string, port int, timeout time.Duration) bool {
	if ip == "" || port <= 0 {
		return false
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func isUDPPortOpen(ip string, port int, timeout time.Duration) bool {
	if ip == "" || port <= 0 {
		return false
	}
	c, err := net.DialTimeout("udp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	_, err = c.Write([]byte{0x00})
	if err != nil {
		return false
	}
	buf := make([]byte, 1)
	if _, err = c.Read(buf); err != nil {
		return false
	}
	return true
}

type httpHeaderResult struct {
	status      int
	contentType string
}

func probeHTTPHeaders(ip string) map[string]string {
	if ip == "" {
		return nil
	}
	result := make(map[string]string)
	for _, scheme := range []string{"http", "https"} {
		port := "80"
		if scheme == "https" {
			port = "443"
		}
		url := scheme + "://" + net.JoinHostPort(ip, port)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "netwise")
		client := &http.Client{Timeout: strategyProbeTimeout}
		res, err := client.Do(req)
		if err != nil {
			continue
		}
		result[scheme+"_status"] = strconv.Itoa(res.StatusCode)
		for _, k := range []string{"Server", "Content-Type", "WWW-Authenticate", "Location"} {
			if v := strings.TrimSpace(res.Header.Get(k)); v != "" {
				result[strings.ToLower(strings.ReplaceAll(k, "-", "_"))] = v
			}
		}
		res.Body.Close()
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func probeFavicon(ip string) struct {
	hash string
	size int
} {
	if ip == "" {
		return struct {
			hash string
			size int
		}{"", 0}
	}
	for _, scheme := range []string{"http", "https"} {
		port := "80"
		if scheme == "https" {
			port = "443"
		}
		url := scheme + "://" + net.JoinHostPort(ip, port) + "/favicon.ico"
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		client := &http.Client{Timeout: strategyProbeTimeout}
		res, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(res.Body, 65536))
		res.Body.Close()
		if len(data) == 0 {
			continue
		}
		s := sha1.Sum(data)
		return struct {
			hash string
			size int
		}{hash: hex.EncodeToString(s[:]), size: len(data)}
	}
	return struct {
		hash string
		size int
	}{"", 0}
}

func probeHTTPPath(ip, pth string) httpHeaderResult {
	if ip == "" {
		return httpHeaderResult{}
	}
	url := "http://" + net.JoinHostPort(ip, "80") + pth
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return httpHeaderResult{}
	}
	client := &http.Client{Timeout: strategyProbeTimeout}
	res, err := client.Do(req)
	if err != nil {
		return httpHeaderResult{}
	}
	defer res.Body.Close()
	return httpHeaderResult{status: res.StatusCode, contentType: res.Header.Get("Content-Type")}
}

func fetchTLSFingerprint(ip string, port int) (subject, issuer, sans string) {
	if ip == "" || port <= 0 {
		return
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: strategyProbeTimeout}, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
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
	vals := []string{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		vals = append(vals, v)
	}
	for _, h := range cert.DNSNames {
		add(h)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	sans = strings.Join(vals, ",")
	return
}

func fetchSSHBanner(ip string) string {
	if ip == "" {
		return ""
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "22"), strategyProbeTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func dhcpLeasePaths() []string {
	if runtime.GOOS == "windows" {
		paths := []string{"C:/Windows/System32/dhcpcsvc/*", "C:/ProgramData/Microsoft/Network/*.txt"}
		out := []string{}
		for _, p := range paths {
			matches, err := filepath.Glob(p)
			if err != nil {
				continue
			}
			out = append(out, matches...)
		}
		return out
	}
	patterns := []string{
		"/var/lib/dhcp/dhclient.leases",
		"/var/lib/dhcp/dhclient*.lease",
		"/var/lib/dhcp/dhclient*.leases",
		"/var/lib/dhcpcd/dhcpcd*.leases",
		"/var/lib/NetworkManager/*.lease",
	}
	out := []string{}
	seen := map[string]struct{}{}
	for _, p := range patterns {
		if strings.ContainsAny(p, "*?[") {
			matches, err := filepath.Glob(p)
			if err != nil {
				continue
			}
			for _, m := range matches {
				if _, ok := seen[m]; !ok {
					seen[m] = struct{}{}
					out = append(out, m)
				}
			}
			continue
		}
		if _, err := os.Stat(p); err == nil {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	return out
}
