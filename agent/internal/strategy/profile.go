package strategy

import (
	"sort"
	"strings"
)

type SpeedCost string

const (
	SpeedVeryLow  SpeedCost = "very_low"
	SpeedLow      SpeedCost = "low"
	SpeedMedium   SpeedCost = "medium"
	SpeedHigh     SpeedCost = "high"
	SpeedVeryHigh SpeedCost = "very_high"
)

func (c SpeedCost) Weight() float64 {
	switch c {
	case SpeedVeryLow:
		return 0.5
	case SpeedLow:
		return 1
	case SpeedMedium:
		return 2
	case SpeedHigh:
		return 4
	case SpeedVeryHigh:
		return 8
	default:
		return 2
	}
}

type ExecutionClass string

const (
	ExecutionActive     ExecutionClass = "active"
	ExecutionPassive    ExecutionClass = "passive"
	ExecutionAmbient    ExecutionClass = "ambient"
	ExecutionContextual ExecutionClass = "contextual"
)

type StrategyTier string

const (
	TierFastPath   StrategyTier = "fast_path"
	TierSecondWave StrategyTier = "second_wave"
	TierExpensive  StrategyTier = "expensive"
	TierContextual StrategyTier = "contextual"
	TierNoise      StrategyTier = "noise"
)

type StrategyAudit struct {
	Name           string         `json:"name"`
	Mode           string         `json:"mode"`
	ExecutionClass ExecutionClass `json:"execution_class"`
	SpeedCost      SpeedCost      `json:"speed_cost"`
	DiscoveryValue int            `json:"discovery_value"`
	LabelingValue  int            `json:"labeling_value"`
	Recommendation StrategyTier   `json:"recommendation"`
	Notes          string         `json:"notes,omitempty"`
}

type StrategyProfile struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	StrategyNames []string `json:"strategy_names"`
}

var strategyAuditOverrides = map[string]StrategyAudit{
	"arp_active_refresh": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 5,
		LabelingValue:  2,
		Recommendation: TierFastPath,
		Notes:          "Cheap identity refresh that improves device presence tracking.",
	},
	"arp_neighbor": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 5,
		LabelingValue:  2,
		Recommendation: TierFastPath,
		Notes:          "Foundation strategy for fast IP-to-MAC attribution.",
	},
	"camera_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedVeryHigh,
		DiscoveryValue: 1,
		LabelingValue:  5,
		Recommendation: TierExpensive,
		Notes:          "Very strong when it hits, but multi-protocol probing is expensive.",
	},
	"cdp_control": {
		ExecutionClass: ExecutionAmbient,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  1,
		Recommendation: TierContextual,
		Notes:          "Infrastructure context from the local segment rather than a per-target identifier.",
	},
	"credentialed_api": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedHigh,
		DiscoveryValue: 1,
		LabelingValue:  4,
		Recommendation: TierExpensive,
		Notes:          "High-value only when credentials exist; not suitable for a default fast lane.",
	},
	"cross_scan_time_correlation": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 1,
		LabelingValue:  1,
		Recommendation: TierContextual,
		Notes:          "Useful history metadata, but not a first-pass identifier.",
	},
	"dhcpv4_options": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Low-cost if local lease files are present, but environment-dependent.",
	},
	"dhcpv6_duid": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Potentially stable identity data, but often absent in IPv4-heavy homes.",
	},
	"directory_service_correlation": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Helpful for managed enterprise naming, weak on consumer networks.",
	},
	"dns_ptr_reverse": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Cheap hostname enrichment when reverse DNS exists.",
	},
	"dns_query_observation": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 1,
		LabelingValue:  1,
		Recommendation: TierSecondWave,
		Notes:          "Can add corroboration, but depends on hostname quality.",
	},
	"evidence_graph_merger": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 1,
		LabelingValue:  1,
		Recommendation: TierContextual,
		Notes:          "Graph stitching is useful for analysis, not for first-hit identification.",
	},
	"firewall_traffic_profile": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedHigh,
		DiscoveryValue: 1,
		LabelingValue:  3,
		Recommendation: TierExpensive,
		Notes:          "Multiple protocol probes with niche payoff; better deferred.",
	},
	"flow_netflow_ipfix": {
		ExecutionClass: ExecutionAmbient,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierContextual,
		Notes:          "Collector-side telemetry, useful only in instrumented environments.",
	},
	"home_api_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedHigh,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierExpensive,
		Notes:          "Broad HTTP path fan-out makes it costly for a fast default profile.",
	},
	"host_event_log_pull": {
		ExecutionClass: ExecutionAmbient,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 1,
		LabelingValue:  1,
		Recommendation: TierNoise,
		Notes:          "Produces real local-host data, but it is weakly tied to remote targets.",
	},
	"http_favicon_fingerprint": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Useful when web UI branding exists, but not a first-pass staple.",
	},
	"http_header_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Moderate-cost web metadata pass that can help on admin endpoints.",
	},
	"icmp_reachability": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 4,
		LabelingValue:  1,
		Recommendation: TierFastPath,
		Notes:          "Cheap reachability confirmation that improves practical device detection.",
	},
	"ipv6_ula_prefix_hints": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 1,
		LabelingValue:  1,
		Recommendation: TierContextual,
		Notes:          "Good IPv6 context, but rarely decisive for a fast LAN scan.",
	},
	"lldp_neighbors": {
		ExecutionClass: ExecutionAmbient,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  1,
		Recommendation: TierContextual,
		Notes:          "Local topology signal that is more segment context than target ID.",
	},
	"llmnr_responder_analysis": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Can be useful on Windows-centric networks, but not universally high-return.",
	},
	"mac_oui_and_localadmin": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierFastPath,
		Notes:          "Near-free enrichment for vendor and address stability hints.",
	},
	"manual_operator_label_fallback": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 0,
		LabelingValue:  5,
		Recommendation: TierFastPath,
		Notes:          "Manual truth should always be kept if configured.",
	},
	"mdns_active": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 3,
		LabelingValue:  4,
		Recommendation: TierFastPath,
		Notes:          "High upside for media, printer, phone, and laptop labeling. Reads from pre-seeded cache so strategy-phase cost is negligible. Moved to fast_path after live benchmarks showed it hits all targets with high observation yield at near-zero extra cost.",
	},
	"mdns_passive": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Low-cost if traffic exists, but often sparse without a longer listen window.",
	},
	"media_device_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedVeryHigh,
		DiscoveryValue: 2,
		LabelingValue:  5,
		Recommendation: TierExpensive,
		Notes:          "Excellent TV/media labeling probe, but one of the most expensive strategies.",
	},
	"media_device_quick_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  5,
		Recommendation: TierSecondWave,
		Notes:          "Targeted TV/camera label probe that keeps only the ports and protocol checks that mattered in scoped-v3 label tracing.",
	},
	"netbios_llmnr_passive": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 4,
		LabelingValue:  3,
		Recommendation: TierFastPath,
		Notes:          "High-yield Windows/host naming signal at low cost.",
	},
	"packet_ttl_os_fingerprint": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Lightweight OS-family hint, but rarely decisive alone.",
	},
	"passive_http_metadata": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Useful for client and admin-UI metadata when passive capture actually sees plaintext HTTP traffic.",
	},
	"passive_service_fingerprint_pcap": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Shared passive packet-derived lane that matters most on client-heavy networks.",
	},
	"passive_ssh_banner": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 1,
		LabelingValue:  1,
		Recommendation: TierContextual,
		Notes:          "Only useful when passive capture already sees SSH traffic.",
	},
	"passive_tls_handshake": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Observed TLS handshakes become strong passive evidence when capture is available.",
	},
	"port_service_correlation": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 3,
		LabelingValue:  3,
		Recommendation: TierFastPath,
		Notes:          "Cheap derived signal that converts open-port hints into usable label evidence.",
	},
	"printer_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedVeryHigh,
		DiscoveryValue: 1,
		LabelingValue:  5,
		Recommendation: TierExpensive,
		Notes:          "Very informative on printers, but too broad and chatty for the fast lane.",
	},
	"radius_8021x_identity": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierContextual,
		Notes:          "Managed-Wi-Fi identity data is high-value when controller or syslog exports exist.",
	},
	"passive_dhcp_fingerprint": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 3,
		LabelingValue:  4,
		Recommendation: TierSecondWave,
		Notes:          "One of the best passive client fingerprints when DHCP traffic or logs are available.",
	},
	"passive_dns_client_profile": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  4,
		Recommendation: TierSecondWave,
		Notes:          "Resolver-side or packet-captured DNS behavior helps classify phones, tablets, and laptops.",
	},
	"passive_tls_client_fingerprint": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  4,
		Recommendation: TierSecondWave,
		Notes:          "TLS ClientHello fingerprints are one of the strongest passive client-device signals.",
	},
	"passive_quic_fingerprint": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Modern mobile traffic increasingly uses QUIC, so this fills a passive blind spot.",
	},
	"passive_ipv6_client_profile": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierContextual,
		Notes:          "Helpful IPv6-side corroboration, especially on privacy-address-heavy mobile devices.",
	},
	"wifi_client_association_telemetry": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 3,
		LabelingValue:  4,
		Recommendation: TierSecondWave,
		Notes:          "Wi-Fi association and roaming telemetry is especially valuable for phones and tablets.",
	},
	"resolver_client_profile": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  4,
		Recommendation: TierSecondWave,
		Notes:          "Resolver logs offer a stronger passive client view than a normal switched-LAN capture.",
	},
	"passive_session_profile": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Router or firewall session exports add useful client behavior signatures without active probing.",
	},
	"rdp_service_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 1,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Worth a second pass for workstation-like endpoints with 3389 exposed.",
	},
	"router_gateway_proc_lookup": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedVeryLow,
		DiscoveryValue: 3,
		LabelingValue:  2,
		Recommendation: TierFastPath,
		Notes:          "Almost free gateway hint that helps isolate router candidates.",
	},
	"smb_info_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Good workstation/server enrichment once the fast path has narrowed targets.",
	},
	"smb_nbns_active": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Useful on Windows-heavy networks, but not broad enough for fast defaults.",
	},
	"snmp_system_identity": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedHigh,
		DiscoveryValue: 2,
		LabelingValue:  5,
		Recommendation: TierExpensive,
		Notes:          "Extremely valuable for routers, printers, and cameras when open, but expensive and often empty.",
	},
	"snmp_trap_event_pull": {
		ExecutionClass: ExecutionAmbient,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierContextual,
		Notes:          "Collector-side telemetry rather than a fast active identification primitive.",
	},
	"ssdp_active": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 4,
		LabelingValue:  4,
		Recommendation: TierFastPath,
		Notes:          "One of the best router/media fast-path strategies when attribution is scoped.",
	},
	"ssdp_passive": {
		ExecutionClass: ExecutionPassive,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 3,
		LabelingValue:  4,
		Recommendation: TierFastPath,
		Notes:          "Complements SSDP active results with minimal incremental cost.",
	},
	"ssh_banner_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierSecondWave,
		Notes:          "Helpful for Unix-like endpoints, but not usually the highest ROI first.",
	},
	"static_ip_lease": {
		ExecutionClass: ExecutionContextual,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 2,
		LabelingValue:  1,
		Recommendation: TierSecondWave,
		Notes:          "Low-cost reservation context when router lease/config files are accessible.",
	},
	"switch_controller_telemetry": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedVeryHigh,
		DiscoveryValue: 1,
		LabelingValue:  3,
		Recommendation: TierExpensive,
		Notes:          "Specialized infrastructure probe with high fan-out cost.",
	},
	"tcp_connect_microset": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 4,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Useful service-shape probe, but it overlaps with the existing discovery sweep and port correlation enough to defer from the default fast path.",
	},
	"tls_cert_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedHigh,
		DiscoveryValue: 1,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Good second-wave enrichment, but 3-port TLS probing is too costly for the first pass.",
	},
	"upnp_description_fetch": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 3,
		LabelingValue:  5,
		Recommendation: TierFastPath,
		Notes:          "High-value follow-up on SSDP hits that often closes the labeling loop.",
	},
	"upnp_service_control": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedHigh,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierExpensive,
		Notes:          "Useful only for deeper device introspection after the main fast path.",
	},
	"voip_telemetry_probe": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedHigh,
		DiscoveryValue: 1,
		LabelingValue:  2,
		Recommendation: TierExpensive,
		Notes:          "Niche specialized probe with substantial protocol fan-out.",
	},
	"wireless_11_beacon": {
		ExecutionClass: ExecutionAmbient,
		SpeedCost:      SpeedLow,
		DiscoveryValue: 1,
		LabelingValue:  1,
		Recommendation: TierNoise,
		Notes:          "High observation count but mostly local-radio context and weak target attribution.",
	},
	"wsd_discovery": {
		ExecutionClass: ExecutionActive,
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 2,
		LabelingValue:  3,
		Recommendation: TierSecondWave,
		Notes:          "Useful for printer and Windows-adjacent devices, but not universal.",
	},
}

func StrategyAuditForName(name string) (StrategyAudit, bool) {
	metadata, ok := StrategyMetadataForName(name)
	if !ok {
		return StrategyAudit{}, false
	}
	base := defaultStrategyAudit(metadata)
	if override, ok := strategyAuditOverrides[metadata.Name]; ok {
		base.ExecutionClass = override.ExecutionClass
		base.SpeedCost = override.SpeedCost
		base.DiscoveryValue = override.DiscoveryValue
		base.LabelingValue = override.LabelingValue
		base.Recommendation = override.Recommendation
		base.Notes = override.Notes
	}
	base.Name = metadata.Name
	base.Mode = metadata.Mode
	return base, true
}

func StrategyAuditCatalog() []StrategyAudit {
	metadata := StrategyMetadataCatalog()
	out := make([]StrategyAudit, 0, len(metadata))
	for _, item := range metadata {
		audit, ok := StrategyAuditForName(item.Name)
		if !ok {
			continue
		}
		out = append(out, audit)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func StrategyProfiles() []StrategyProfile {
	mediumStrategies := strategiesForTiers(TierFastPath, TierSecondWave)
	mediumStrategies = appendMissingStrategies(mediumStrategies, "media_device_probe")
	return []StrategyProfile{
		{
			Name:          "full",
			Description:   "Run the full-capability scanner with all registered discovery, contextual, and specialized probes.",
			StrategyNames: strategyNamesInOrder(AllStrategies()),
		},
		{
			Name:          "medium",
			Description:   "Run the fast path plus targeted second-wave enrichers that add label quality without the heaviest long-tail probes.",
			StrategyNames: mediumStrategies,
		},
		{
			Name:          "fast",
			Description:   "Prioritize high-value, lower-cost discovery and attribution strategies for quick practical identification.",
			StrategyNames: strategiesForTiers(TierFastPath),
		},
		{
			Name:        "label_core",
			Description: "Focused label profile covering the most valuable fast-path strategies: ARP identity, vendor OUI, mDNS service browsing, NetBIOS passive naming, SSDP/UPnP device description, media port probing, and operator overrides.",
			StrategyNames: []string{
				"arp_neighbor",
				"arp_active_refresh",
				"mac_oui_and_localadmin",
				"mdns_active",
				"netbios_llmnr_passive",
				"ssdp_active",
				"upnp_description_fetch",
				"media_device_quick_probe",
				"manual_operator_label_fallback",
			},
		},
	}
}

func ResolveProfile(name string) (StrategyProfile, bool) {
	normalized := normalizeProfileName(name)
	for _, profile := range StrategyProfiles() {
		if profile.Name == normalized {
			return profile, true
		}
	}
	return StrategyProfile{}, false
}

func ProfileNames() []string {
	profiles := StrategyProfiles()
	out := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, profile.Name)
	}
	sort.Strings(out)
	return out
}

func ProfileStrategyNames(name string) []string {
	profile, ok := ResolveProfile(name)
	if !ok {
		return nil
	}
	return append([]string{}, profile.StrategyNames...)
}

func defaultStrategyAudit(metadata StrategyMetadata) StrategyAudit {
	return StrategyAudit{
		Name:           metadata.Name,
		Mode:           metadata.Mode,
		ExecutionClass: executionClassFromMetadata(metadata),
		SpeedCost:      SpeedMedium,
		DiscoveryValue: 1,
		LabelingValue:  1,
		Recommendation: TierContextual,
	}
}

func executionClassFromMetadata(metadata StrategyMetadata) ExecutionClass {
	switch strings.ToLower(strings.TrimSpace(metadata.Mode)) {
	case "active":
		return ExecutionActive
	case "passive":
		return ExecutionPassive
	case "operator", "derived":
		return ExecutionContextual
	default:
		return ExecutionContextual
	}
}

func strategiesForTiers(tiers ...StrategyTier) []string {
	allowed := make(map[StrategyTier]struct{}, len(tiers))
	for _, tier := range tiers {
		allowed[tier] = struct{}{}
	}

	out := make([]string, 0, len(strategyAuditOverrides))
	for _, strategy := range AllStrategies() {
		audit, ok := StrategyAuditForName(strategy.Name())
		if !ok {
			continue
		}
		if _, ok := allowed[audit.Recommendation]; ok {
			out = append(out, audit.Name)
		}
	}
	return out
}

func strategyNamesInOrder(strategies []Strategy) []string {
	out := make([]string, 0, len(strategies))
	for _, strategy := range strategies {
		out = append(out, strategy.Name())
	}
	return out
}

func normalizeProfileName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func appendMissingStrategies(base []string, extras ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(extras))
	out := make([]string, 0, len(base)+len(extras))
	for _, name := range base {
		normalized := normalizeProfileName(name)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, name)
	}
	for _, name := range extras {
		normalized := normalizeProfileName(name)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, name)
	}
	return out
}
