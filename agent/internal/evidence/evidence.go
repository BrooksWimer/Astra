package evidence

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/netwise/agent/internal/store"
)

type EvidenceFamily string
type EvidenceTier string
type IdentitySource string

const (
	FamilyIdentity           EvidenceFamily = "identity"
	FamilyDHCP               EvidenceFamily = "dhcp"
	FamilyDNS                EvidenceFamily = "dns"
	FamilyDiscoveryMDNS      EvidenceFamily = "mdns"
	FamilyDiscoverySSDP      EvidenceFamily = "ssdp"
	FamilyDiscoveryWSD       EvidenceFamily = "wsd"
	FamilyServiceDiscovery   EvidenceFamily = "service_discovery"
	FamilyServiceFingerprint EvidenceFamily = "service_fingerprint"
	FamilyDeviceDescription  EvidenceFamily = "device_description"
	FamilyTopology           EvidenceFamily = "topology"
	FamilySNMP               EvidenceFamily = "snmp"
	FamilyPorts              EvidenceFamily = "ports"
	FamilyBehavior           EvidenceFamily = "behavior"
	FamilyCorrelation        EvidenceFamily = "correlation"
	FamilyWifi               EvidenceFamily = "wifi"
	FamilySecurityOps        EvidenceFamily = "security_ops"
	FamilyUnknown            EvidenceFamily = "unknown"

	TierStrong     EvidenceTier = "strong"
	TierMedium     EvidenceTier = "medium"
	TierWeak       EvidenceTier = "weak"
	TierContextual EvidenceTier = "contextual"

	IdentitySourceMAC      IdentitySource = "mac"
	IdentitySourceDUID     IdentitySource = "dhcpv6_duid"
	IdentitySourceHostname IdentitySource = "hostname"
	IdentitySourceIP       IdentitySource = "ip"
	IdentitySourceDeviceID IdentitySource = "device_id"
	IdentitySourceUnknown  IdentitySource = "unknown"
)

type PrivacyMode string

const (
	PrivacyModeFull         PrivacyMode = "full"
	PrivacyModeHashedDomain PrivacyMode = "hashed-domain"
	PrivacyModeCategoryOnly PrivacyMode = "category-only"
)

type PrivacyConfig struct {
	DNSPrivacyMode PrivacyMode
}

type Evidence struct {
	DeviceID       string
	Strategy       string
	Key            string
	Value          string
	CanonicalKey   string
	CanonicalValue string
	Family         EvidenceFamily
	Tier           EvidenceTier
	Timestamp      time.Time
	Details        map[string]string
	SourceHostname string
}

type IdentityResolution struct {
	Key              string         `json:"key"`
	Source           IdentitySource `json:"source"`
	PrimaryValue     string         `json:"primary_value,omitempty"`
	FallbackValue    string         `json:"fallback_value,omitempty"`
	Volatile         bool           `json:"volatile"`
	VolatilityReason string         `json:"volatility_reason,omitempty"`
	VolatilityScore  float64        `json:"volatility_score,omitempty"`
	Evidence         []string       `json:"evidence,omitempty"`
}

type Profile struct {
	DeviceID                string
	Signals                 []Evidence
	FirstSeen               time.Time
	LastSeen                time.Time
	ObservedDuration        time.Duration
	SignalVolume            int
	SignalCounts            map[string]int
	StrategyCounts          map[string]int
	FamilyCounts            map[EvidenceFamily]int
	TierCounts              map[EvidenceTier]int
	TopSignals              map[string]int
	Identity                IdentityResolution
	ObservationCount        int
	TemporalBins            map[string]int
	HitFrequency            float64
	RepeatedObservations    int
	RepeatedObservationKeys []string
	StaleSignalScore        float64
	UniqueSignals           int
}

func emptyProfile(deviceID string) Profile {
	return Profile{
		DeviceID:       deviceID,
		FirstSeen:      time.Time{},
		LastSeen:       time.Time{},
		SignalCounts:   make(map[string]int),
		StrategyCounts: make(map[string]int),
		FamilyCounts:   make(map[EvidenceFamily]int),
		TierCounts:     make(map[EvidenceTier]int),
		TopSignals:     make(map[string]int),
		TemporalBins:   make(map[string]int),
	}
}

func FromObservation(obs store.Observation, cfg PrivacyConfig) Evidence {
	family, tier := resolveFamily(obs.Strategy, obs.Key, obs.Value, obs.Details)
	tier = adjustEvidenceTier(strings.ToLower(strings.TrimSpace(obs.Strategy)), tier, obs.Details)
	value := canonicalizeValue(obs.Key, obs.Value, cfg)
	return Evidence{
		DeviceID:       obs.MAC,
		Strategy:       obs.Strategy,
		Key:            strings.ToLower(strings.TrimSpace(obs.Key)),
		Value:          obs.Value,
		CanonicalKey:   strings.ToLower(strings.TrimSpace(obs.Strategy + "|" + obs.Key)),
		CanonicalValue: value,
		Family:         family,
		Tier:           tier,
		Timestamp:      time.UnixMilli(obs.Timestamp),
		Details:        obs.Details,
		SourceHostname: obs.Hostname,
	}
}

func adjustEvidenceTier(strategyName string, tier EvidenceTier, details map[string]string) EvidenceTier {
	matchQuality := ""
	sourceScope := ""
	if details != nil {
		matchQuality = strings.ToLower(strings.TrimSpace(details["match_quality"]))
		sourceScope = strings.ToLower(strings.TrimSpace(details["source_scope"]))
	}
	switch matchQuality {
	case "ambient_context", "unmatched":
		return TierContextual
	case "strong_inferred_match":
		return downgradeTier(tier)
	}
	if (strategyName == "host_event_log_pull" || strategyName == "wireless_11_beacon") && matchQuality != "direct_match" && matchQuality != "strong_inferred_match" {
		return TierContextual
	}
	if strings.Contains(sourceScope, "passive") && matchQuality == "" {
		return TierContextual
	}
	return tier
}

func downgradeTier(tier EvidenceTier) EvidenceTier {
	switch tier {
	case TierStrong:
		return TierMedium
	case TierMedium:
		return TierWeak
	case TierWeak:
		return TierContextual
	default:
		return TierContextual
	}
}

func BuildProfile(deviceID string, observations []store.Observation, cfg PrivacyConfig) Profile {
	profile := emptyProfile(deviceID)
	profile.Identity = ResolveIdentityKey(deviceID)
	profile.ObservationCount = len(observations)
	seen := make(map[string]struct{}, len(observations))
	rawCounts := make(map[string]int, len(observations))
	now := time.Now().UTC()

	for _, obs := range observations {
		e := FromObservation(obs, cfg)
		if e.DeviceID == "" {
			e.DeviceID = deviceID
		}
		sigKey := signalKey(e)
		rawCounts[sigKey]++
		if _, ok := seen[sigKey]; ok {
			continue
		}
		seen[sigKey] = struct{}{}

		profile.Signals = append(profile.Signals, e)
		profile.SignalCounts[e.CanonicalKey]++
		profile.StrategyCounts[e.Strategy]++
		profile.TopSignals[e.Strategy+"|"+e.Key]++
		profile.FamilyCounts[e.Family]++
		profile.TierCounts[e.Tier]++
		profile.SignalVolume++
		profile.TemporalBins[temporalBin(now.Sub(e.Timestamp))]++
		profile.StaleSignalScore += StaleSignalDecay(now.Sub(e.Timestamp))

		if profile.FirstSeen.IsZero() || e.Timestamp.Before(profile.FirstSeen) {
			profile.FirstSeen = e.Timestamp
		}
		if profile.LastSeen.IsZero() || e.Timestamp.After(profile.LastSeen) {
			profile.LastSeen = e.Timestamp
		}
	}
	if !profile.FirstSeen.IsZero() && !profile.LastSeen.IsZero() {
		profile.ObservedDuration = profile.LastSeen.Sub(profile.FirstSeen)
	}
	for key, count := range rawCounts {
		if count <= 1 {
			continue
		}
		profile.RepeatedObservations += count - 1
		profile.RepeatedObservationKeys = append(profile.RepeatedObservationKeys, key)
	}
	if profile.SignalVolume > 0 {
		profile.UniqueSignals = profile.SignalVolume
		profile.HitFrequency = float64(profile.ObservationCount) / math.Max(profile.ObservedDuration.Seconds(), 1)
		profile.StaleSignalScore = profile.StaleSignalScore / float64(profile.SignalVolume)
	}
	if profile.SignalVolume > 0 && profile.HitFrequency == 0 {
		profile.HitFrequency = float64(profile.SignalVolume)
	}
	sort.Strings(profile.RepeatedObservationKeys)
	return profile
}

func signalKey(e Evidence) string {
	if e.Strategy == "" {
		return fmt.Sprintf("%s|%s|%s", e.Key, e.CanonicalValue, strings.Join(sortedDetailPairs(e.Details), ","))
	}
	return fmt.Sprintf("%s|%s|%s|%s", e.Strategy, e.Key, e.CanonicalValue, strings.Join(sortedDetailPairs(e.Details), ","))
}

func sortedDetailPairs(details map[string]string) []string {
	if len(details) == 0 {
		return nil
	}
	keys := make([]string, 0, len(details))
	for k := range details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		v := strings.TrimSpace(details[k])
		out = append(out, k+"="+v)
	}
	return out
}

func flattenDetailsKeys(details map[string]string) []string {
	pairs := sortedDetailPairs(details)
	if len(pairs) == 0 {
		return nil
	}
	out := make([]string, len(pairs))
	for i, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		out[i] = parts[0]
	}
	return out
}

func DeviceKeyFrom(d *store.Device) string {
	return ResolveDeviceIdentity(d).Key
}

// StableDeviceKey is the public helper most callers should use when they need
// a deterministic, normalized identity key for a device.
func StableDeviceKey(d *store.Device) string {
	return DeviceKeyFrom(d)
}

// StableDeviceIdentity exposes the full identity-resolution result, including
// volatility metadata that downstream callers can surface or log.
func StableDeviceIdentity(d *store.Device) IdentityResolution {
	return ResolveDeviceIdentity(d)
}

func ResolveDeviceIdentity(d *store.Device) IdentityResolution {
	if d == nil {
		return IdentityResolution{
			Key:              "unknown",
			Source:           IdentitySourceUnknown,
			Volatile:         true,
			VolatilityReason: "missing device",
			VolatilityScore:  1,
		}
	}

	if mac := normalizeIdentityMAC(d.MAC); isMACAddress(mac) {
		return IdentityResolution{
			Key:             mac,
			Source:          IdentitySourceMAC,
			PrimaryValue:    mac,
			VolatilityScore: 0,
			Evidence:        []string{"mac"},
		}
	}

	if duid := findDeviceObservationValue(d, "dhcpv6_duid", "duid"); duid != "" {
		return IdentityResolution{
			Key:             "duid:" + duid,
			Source:          IdentitySourceDUID,
			PrimaryValue:    duid,
			Evidence:        []string{"dhcpv6_duid"},
			VolatilityScore: 0.1,
		}
	}

	hostname := ""
	if d.Hostname != nil {
		hostname = normalizeIdentityHostname(*d.Hostname)
	}
	ip := strings.TrimSpace(d.IP)

	if hostname != "" && ip != "" {
		return IdentityResolution{
			Key:              "host:" + hostname,
			Source:           IdentitySourceHostname,
			PrimaryValue:     hostname,
			FallbackValue:    ip,
			Volatile:         true,
			VolatilityReason: "hostname/ip fallback can rebind",
			VolatilityScore:  0.8,
			Evidence:         []string{"hostname", "ip"},
		}
	}
	if hostname != "" {
		return IdentityResolution{
			Key:              "host:" + hostname,
			Source:           IdentitySourceHostname,
			PrimaryValue:     hostname,
			Volatile:         true,
			VolatilityReason: "hostname fallback is less stable than mac/duid",
			VolatilityScore:  0.7,
			Evidence:         []string{"hostname"},
		}
	}
	if ip != "" {
		return IdentityResolution{
			Key:              "ip:" + ip,
			Source:           IdentitySourceIP,
			PrimaryValue:     ip,
			Volatile:         true,
			VolatilityReason: "ip-only identity can change with DHCP",
			VolatilityScore:  0.9,
			Evidence:         []string{"ip"},
		}
	}
	if id := strings.TrimSpace(d.ID); id != "" {
		return IdentityResolution{
			Key:              strings.ToLower(strings.TrimSpace(id)),
			Source:           IdentitySourceDeviceID,
			PrimaryValue:     id,
			Volatile:         true,
			VolatilityReason: "device_id fallback",
			VolatilityScore:  0.5,
			Evidence:         []string{"device_id"},
		}
	}

	return IdentityResolution{
		Key:              "unknown",
		Source:           IdentitySourceUnknown,
		Volatile:         true,
		VolatilityReason: "no stable identity signal",
		VolatilityScore:  1,
	}
}

func ResolveIdentityKey(key string) IdentityResolution {
	normalized := strings.TrimSpace(strings.ToLower(key))
	switch {
	case normalized == "":
		return IdentityResolution{Key: "unknown", Source: IdentitySourceUnknown, Volatile: true, VolatilityReason: "empty key", VolatilityScore: 1}
	case isMACAddress(normalizeIdentityMAC(normalized)):
		mac := normalizeIdentityMAC(normalized)
		return IdentityResolution{Key: mac, Source: IdentitySourceMAC, PrimaryValue: mac, VolatilityScore: 0}
	case strings.HasPrefix(normalized, "duid:"):
		return IdentityResolution{Key: normalized, Source: IdentitySourceDUID, PrimaryValue: strings.TrimPrefix(normalized, "duid:"), VolatilityScore: 0.1}
	case strings.HasPrefix(normalized, "host:"):
		return IdentityResolution{Key: normalized, Source: IdentitySourceHostname, PrimaryValue: strings.TrimPrefix(normalized, "host:"), Volatile: true, VolatilityReason: "hostname fallback", VolatilityScore: 0.7}
	case strings.HasPrefix(normalized, "ip:"):
		return IdentityResolution{Key: normalized, Source: IdentitySourceIP, PrimaryValue: strings.TrimPrefix(normalized, "ip:"), Volatile: true, VolatilityReason: "ip fallback", VolatilityScore: 0.9}
	default:
		return IdentityResolution{Key: normalized, Source: IdentitySourceDeviceID, PrimaryValue: normalized, Volatile: true, VolatilityReason: "structured key fallback", VolatilityScore: 0.4}
	}
}

// StableIdentityFromKey normalizes an already-resolved identity key back into
// structured metadata. It is useful when only a key string is available.
func StableIdentityFromKey(key string) IdentityResolution {
	return ResolveIdentityKey(key)
}

func normalizeIdentityMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return ""
	}
	mac = strings.ReplaceAll(mac, "-", ":")
	if len(mac) == 12 && !strings.Contains(mac, ":") {
		parts := make([]string, 0, 6)
		for i := 0; i < len(mac); i += 2 {
			parts = append(parts, mac[i:i+2])
		}
		mac = strings.Join(parts, ":")
	}
	return mac
}

func normalizeIdentityHostname(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimSuffix(host, ".local")
	return host
}

func isMACAddress(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return false
	}
	parts := strings.Split(v, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		for _, r := range p {
			if !strings.ContainsRune("0123456789abcdef", r) {
				return false
			}
		}
	}
	return true
}

func findDeviceObservationValue(d *store.Device, strategy, key string) string {
	if d == nil {
		return ""
	}
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	key = strings.ToLower(strings.TrimSpace(key))
	for _, obs := range d.Observations {
		if strings.ToLower(strings.TrimSpace(obs.Strategy)) != strategy {
			continue
		}
		if key != "" {
			if strings.ToLower(strings.TrimSpace(obs.Key)) != key && !strings.Contains(strings.ToLower(strings.TrimSpace(obs.Key)), key) {
				continue
			}
		}
		v := strings.TrimSpace(strings.ToLower(obs.Value))
		if v != "" {
			return v
		}
	}
	return ""
}

func canonicalizeValue(key, value string, cfg PrivacyConfig) string {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return ""
	}

	switch cfg.DNSPrivacyMode {
	case PrivacyModeHashedDomain:
		if key == "ptr" || strings.Contains(key, "dns") || key == "hostname" {
			sum := sha1.Sum([]byte(strings.ToLower(strings.TrimSuffix(v, "."))))
			return hex.EncodeToString(sum[:8])
		}
	case PrivacyModeCategoryOnly:
		if key == "ptr" || strings.Contains(key, "dns") || key == "hostname" {
			if strings.Contains(v, ".") {
				parts := strings.Split(v, ".")
				if len(parts) == 0 {
					return "dns_category:unstructured"
				}
				return "dns_category:" + parts[len(parts)-1]
			}
			return "dns_category:unstructured"
		}
	case PrivacyModeFull, "":
		// keep raw
	}
	return v
}

func resolveFamily(strategy string, key string, value string, details map[string]string) (EvidenceFamily, EvidenceTier) {
	s := strings.ToLower(strings.TrimSpace(strategy))
	k := strings.ToLower(strings.TrimSpace(key))
	v := strings.ToLower(strings.TrimSpace(value))
	detailsJoined := strings.ToLower(strings.Join(sortedDetailPairs(details), " "))

	switch s {
	case "arp_active_refresh", "arp_neighbor", "mac_oui_and_localadmin":
		return FamilyIdentity, TierWeak
	case "netbios_llmnr_passive", "llmnr_responder_analysis":
		// NetBIOS machine name and LLMNR query name are real identity signals, not just port observations
		return FamilyIdentity, TierMedium
	case "dhcpv4_options", "dhcpv6_duid", "static_ip_lease", "lease_match":
		if k == "duid" || strings.Contains(v, "duid") {
			return FamilyDHCP, TierStrong
		}
		return FamilyDHCP, TierMedium
	case "dns_ptr_reverse", "dns_query_observation", "dns_reverse", "dns_queries":
		return FamilyDNS, TierWeak
	case "mdns_active", "mdns_passive":
		if k == "mdns_service" || strings.Contains(v, "_ipp") || strings.Contains(v, "airplay") {
			return FamilyDiscoveryMDNS, TierStrong
		}
		return FamilyDiscoveryMDNS, TierMedium
	case "ssdp_active", "ssdp_passive":
		if k == "ssdp_st" || strings.Contains(v, "urn:schemas-upnp-org") {
			return FamilyDiscoverySSDP, TierStrong
		}
		return FamilyDiscoverySSDP, TierMedium
	case "upnp_description_fetch", "upnp_service_control":
		return FamilyDeviceDescription, TierStrong
	case "wsd_discovery":
		return FamilyDiscoveryWSD, TierStrong
	case "lldp_neighbors", "cdp_control", "router_gateway_proc_lookup":
		return FamilyTopology, TierStrong
	case "http_header_probe", "passive_http_metadata", "http_favicon_fingerprint", "http_api_probe", "home_api_probe", "credentialed_api":
		return FamilyServiceFingerprint, TierMedium
	case "passive_tls_client_fingerprint":
		return FamilyServiceFingerprint, TierMedium
	case "passive_dhcp_fingerprint":
		return FamilyDHCP, TierMedium
	case "passive_dns_client_profile", "resolver_client_profile":
		return FamilyDNS, TierMedium
	case "passive_quic_fingerprint":
		return FamilyServiceFingerprint, TierMedium
	case "passive_ipv6_client_profile":
		return FamilyBehavior, TierWeak
	case "wifi_client_association_telemetry":
		return FamilyWifi, TierMedium
	case "passive_session_profile":
		return FamilyBehavior, TierMedium
	case "tcp_connect_microset", "port_service_correlation":
		return FamilyPorts, TierWeak
	case "icmp_reachability":
		return FamilyBehavior, TierContextual
	case "packet_ttl_os_fingerprint":
		return FamilyBehavior, TierMedium
	case "passive_tls_handshake", "tls_cert_probe":
		return FamilyServiceFingerprint, TierMedium
	case "passive_ssh_banner", "ssh_banner_probe":
		return FamilyServiceFingerprint, TierWeak
	case "flow_netflow_ipfix", "firewall_traffic_profile", "flow_like", "timing":
		return FamilyBehavior, TierMedium
	case "wireless_11_beacon":
		return FamilyWifi, TierContextual
	case "cross_scan_time_correlation", "manual_operator_label_fallback", "host_event_log_pull", "directory_service_correlation", "evidence_graph_merger", "history":
		return FamilyCorrelation, TierContextual
	case "radius_8021x_identity", "snmp_system_identity":
		return FamilySNMP, TierStrong
	case "snmp_trap_event_pull", "smb_info_probe", "switch_controller_telemetry", "voip_telemetry_probe", "rdp_service_probe", "media_device_probe", "media_device_quick_probe", "printer_probe", "camera_probe":
		return FamilySecurityOps, TierMedium
	default:
		switch {
		case strings.HasPrefix(k, "udp_") || strings.HasPrefix(k, "tcp_") || k == "ports":
			return FamilyPorts, TierWeak
		case k == "gateway" || k == "evidence_graph" || k == "scan_time" || strings.Contains(v, "peer"):
			return FamilyBehavior, TierContextual
		case strings.Contains(k, "hostname") || strings.Contains(k, "ip") || strings.Contains(k, "mac") || strings.Contains(k, "vendor"):
			return FamilyIdentity, TierWeak
		case strings.Contains(k, "lease") || strings.Contains(k, "duid"):
			return FamilyDHCP, TierMedium
		case strings.Contains(k, "printer") || strings.Contains(k, "camera") || strings.Contains(k, "router") || strings.Contains(detailsJoined, "manufacturer=") || strings.Contains(detailsJoined, "model="):
			return FamilyServiceDiscovery, TierContextual
		case strings.HasPrefix(k, "tls_") || strings.Contains(k, "tls"):
			return FamilyServiceFingerprint, TierWeak
		case strings.HasPrefix(k, "http_"):
			return FamilyServiceFingerprint, TierWeak
		case strings.Contains(k, "domain") || strings.Contains(v, "dns_category"):
			return FamilyDNS, TierContextual
		case strings.Contains(k, "mdns") || strings.Contains(k, "ssdp"):
			return FamilyServiceDiscovery, TierContextual
		}
	}
	return FamilyUnknown, TierWeak
}

func temporalBin(age time.Duration) string {
	if age <= 0 {
		return "fresh"
	}
	switch {
	case age < 5*time.Minute:
		return "fresh_5m"
	case age < time.Hour:
		return "recent_1h"
	case age < 24*time.Hour:
		return "recent_24h"
	case age < 7*24*time.Hour:
		return "stale_7d"
	default:
		return "stale_7d_plus"
	}
}

func StaleSignalDecay(age time.Duration) float64 {
	if age <= 0 {
		return 1
	}
	hours := age.Hours()
	if hours < 0 {
		hours = 0
	}
	decay := math.Exp(-hours / 48.0)
	if decay < 0.01 {
		return 0.01
	}
	return decay
}
