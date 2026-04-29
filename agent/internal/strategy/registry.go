package strategy

import (
	"sort"
	"strings"
)

type StrategyMetadata struct {
	Name                string   `json:"name"`
	Mode                string   `json:"mode"` // active | passive | hybrid | operator | derived
	RequiresPrivilege   bool     `json:"requires_privilege,omitempty"`
	SupportsCredentials bool     `json:"supports_credentials,omitempty"`
	ExplicitOnly        bool     `json:"explicit_only,omitempty"`
	Transports          []string `json:"transports,omitempty"`
	ExpectedKeys        []string `json:"expected_keys,omitempty"`
}

var strategyMetadata = map[string]StrategyMetadata{
	"arp_neighbor":                      {Name: "arp_neighbor", Mode: "active", Transports: []string{"l2", "arp"}, ExpectedKeys: []string{"neighbor_ip", "neighbor_mac", "neighbor_state", "neighbor_interface", "neighbor_type"}},
	"mac_oui_and_localadmin":            {Name: "mac_oui_and_localadmin", Mode: "derived", Transports: []string{"mac"}, ExpectedKeys: []string{"vendor", "locally_admin", "multicast", "oui_prefix"}},
	"dhcpv4_options":                    {Name: "dhcpv4_options", Mode: "derived", Transports: []string{"dhcpv4", "filesystem"}, ExpectedKeys: []string{"dhcpv4_hostname", "dhcpv4_client_identifier", "dhcpv4_vendor_class", "dhcpv4_requested_ip", "dhcpv4_server_identifier"}},
	"dhcpv6_duid":                       {Name: "dhcpv6_duid", Mode: "derived", Transports: []string{"dhcpv6", "filesystem"}, ExpectedKeys: []string{"dhcpv6_duid", "dhcpv6_iaid", "dhcpv6_server_duid", "dhcpv6_hostname"}},
	"static_ip_lease":                   {Name: "static_ip_lease", Mode: "derived", Transports: []string{"dhcp", "filesystem"}, ExpectedKeys: []string{"lease_kind", "lease_expiry", "reservation_name", "reservation_source"}},
	"dns_ptr_reverse":                   {Name: "dns_ptr_reverse", Mode: "active", Transports: []string{"dns"}, ExpectedKeys: []string{"ptr", "dns_status", "dns_resolver"}},
	"dns_query_observation":             {Name: "dns_query_observation", Mode: "active", Transports: []string{"dns"}, ExpectedKeys: []string{"dns_query", "dns_record_type", "dns_status", "dns_cname"}},
	"mdns_passive":                      {Name: "mdns_passive", Mode: "passive", Transports: []string{"mdns", "udp/5353", "pcap"}, ExpectedKeys: []string{"mdns_service", "mdns_instance", "mdns_hostname", "mdns_query_name", "mdns_query_type", "mdns_query_service_family", "mdns_ttl", "mdns_interface"}},
	"mdns_active":                       {Name: "mdns_active", Mode: "active", Transports: []string{"mdns", "udp/5353"}, ExpectedKeys: []string{"mdns_service", "mdns_instance", "mdns_hostname", "mdns_port", "mdns_txt", "mdns_interface"}},
	"ssdp_passive":                      {Name: "ssdp_passive", Mode: "passive", Transports: []string{"ssdp", "udp/1900", "pcap"}, ExpectedKeys: []string{"ssdp_st", "ssdp_usn", "ssdp_server", "ssdp_location", "ssdp_nt", "ssdp_nts", "ssdp_cache_control", "ssdp_source_ip", "ssdp_interface"}},
	"ssdp_active":                       {Name: "ssdp_active", Mode: "active", Transports: []string{"ssdp", "udp/1900"}, ExpectedKeys: []string{"ssdp_st", "ssdp_usn", "ssdp_server", "ssdp_location", "ssdp_cache_control"}},
	"upnp_description_fetch":            {Name: "upnp_description_fetch", Mode: "active", Transports: []string{"http", "upnp"}, ExpectedKeys: []string{"upnp_device_type", "upnp_manufacturer", "upnp_model", "upnp_model_number", "upnp_friendly", "upnp_udn", "upnp_presentation_url"}},
	"netbios_llmnr_passive":             {Name: "netbios_llmnr_passive", Mode: "passive", Transports: []string{"nbns", "llmnr", "udp/137", "udp/5355"}, ExpectedKeys: []string{"netbios_name", "netbios_suffix", "netbios_role", "llmnr_name", "llmnr_source"}},
	"wsd_discovery":                     {Name: "wsd_discovery", Mode: "active", Transports: []string{"wsd", "udp/3702"}, ExpectedKeys: []string{"wsd_xaddr", "wsd_type", "wsd_scope", "wsd_uuid", "wsd_metadata_version"}},
	"lldp_neighbors":                    {Name: "lldp_neighbors", Mode: "passive", RequiresPrivilege: true, Transports: []string{"lldp", "ethernet"}, ExpectedKeys: []string{"lldp_chassis_id", "lldp_port_id", "lldp_system_name", "lldp_system_description", "lldp_capabilities", "lldp_management_ip", "lldp_vlan"}},
	"cdp_control":                       {Name: "cdp_control", Mode: "passive", RequiresPrivilege: true, Transports: []string{"cdp", "ethernet"}, ExpectedKeys: []string{"cdp_chassis_id", "cdp_port_id", "cdp_platform", "cdp_software", "cdp_capabilities", "cdp_management_ip", "cdp_vlan"}},
	"radius_8021x_identity":             {Name: "radius_8021x_identity", Mode: "passive", RequiresPrivilege: true, SupportsCredentials: true, Transports: []string{"radius", "802.1x", "syslog"}, ExpectedKeys: []string{"radius_identity", "radius_realm", "radius_eap_type", "radius_auth_result", "radius_vlan", "radius_role"}},
	"wireless_11_beacon":                {Name: "wireless_11_beacon", Mode: "passive", RequiresPrivilege: true, Transports: []string{"802.11"}, ExpectedKeys: []string{"wireless_bssid", "wireless_ssid", "wireless_channel", "wireless_rssi", "wireless_security", "wireless_capabilities"}},
	"passive_service_fingerprint_pcap":  {Name: "passive_service_fingerprint_pcap", Mode: "passive", RequiresPrivilege: true, Transports: []string{"pcap"}, ExpectedKeys: []string{"passive_flow_transport", "passive_flow_src_port", "passive_flow_dst_port", "passive_flow_protocol", "passive_flow_peer", "passive_flow_direction", "passive_flow_count", "passive_flow_status"}},
	"passive_tls_handshake":             {Name: "passive_tls_handshake", Mode: "passive", RequiresPrivilege: true, Transports: []string{"tls", "pcap"}, ExpectedKeys: []string{"passive_tls_version", "passive_tls_alpn", "passive_tls_sni", "passive_tls_cipher", "passive_tls_cert_subject", "passive_tls_cert_issuer", "passive_tls_status"}},
	"passive_ssh_banner":                {Name: "passive_ssh_banner", Mode: "passive", RequiresPrivilege: true, Transports: []string{"ssh", "pcap"}, ExpectedKeys: []string{"passive_ssh_banner", "passive_ssh_software", "passive_ssh_proto", "passive_ssh_status"}},
	"passive_http_metadata":             {Name: "passive_http_metadata", Mode: "passive", RequiresPrivilege: true, Transports: []string{"http", "pcap"}, ExpectedKeys: []string{"passive_http_host", "passive_http_user_agent", "passive_http_server", "passive_http_path_hint", "passive_http_status_code", "passive_http_status"}},
	"icmp_reachability":                 {Name: "icmp_reachability", Mode: "active", RequiresPrivilege: true, Transports: []string{"icmp"}, ExpectedKeys: []string{"icmp_status", "icmp_rtt_ms", "icmp_ttl", "icmp_type", "icmp_code"}},
	"arp_active_refresh":                {Name: "arp_active_refresh", Mode: "active", Transports: []string{"arp", "icmp", "tcp"}, ExpectedKeys: []string{"neighbor_ip", "neighbor_mac", "neighbor_state", "neighbor_interface", "neighbor_age"}},
	"tcp_connect_microset":              {Name: "tcp_connect_microset", Mode: "active", Transports: []string{"tcp"}, ExpectedKeys: []string{"ports", "tcp_rtt_ms", "tcp_options", "tcp_service_hint"}},
	"http_header_probe":                 {Name: "http_header_probe", Mode: "active", Transports: []string{"http", "https"}, ExpectedKeys: []string{"http_status", "http_server", "http_content_type", "http_title", "http_location", "http_authenticate"}},
	"http_favicon_fingerprint":          {Name: "http_favicon_fingerprint", Mode: "active", Transports: []string{"http", "https"}, ExpectedKeys: []string{"favicon_sha1", "favicon_sha256", "favicon_mmh3", "favicon_size", "favicon_path"}},
	"tls_cert_probe":                    {Name: "tls_cert_probe", Mode: "active", Transports: []string{"tls"}, ExpectedKeys: []string{"tls_subject", "tls_issuer", "tls_sans", "tls_serial", "tls_fingerprint_sha256", "tls_version", "tls_cipher", "tls_alpn"}},
	"ssh_banner_probe":                  {Name: "ssh_banner_probe", Mode: "active", Transports: []string{"ssh"}, ExpectedKeys: []string{"ssh_banner", "ssh_product", "ssh_kex", "ssh_hostkey_algorithm", "ssh_auth_methods"}},
	"smb_info_probe":                    {Name: "smb_info_probe", Mode: "active", Transports: []string{"smb"}, ExpectedKeys: []string{"smb_dialect", "smb_signing", "smb_guid", "smb_capabilities", "smb_target_info"}},
	"smb_nbns_active":                   {Name: "smb_nbns_active", Mode: "active", Transports: []string{"nbns", "udp/137"}, ExpectedKeys: []string{"nbns_name", "nbns_suffix", "nbns_group", "nbns_mac"}},
	"upnp_service_control":              {Name: "upnp_service_control", Mode: "active", Transports: []string{"upnp", "soap"}, SupportsCredentials: true, ExpectedKeys: []string{"upnp_service_type", "upnp_action", "upnp_state_variable", "upnp_control_url"}},
	"snmp_system_identity":              {Name: "snmp_system_identity", Mode: "active", Transports: []string{"snmp"}, SupportsCredentials: true, ExpectedKeys: []string{"snmp_sysdescr", "snmp_sysobjectid", "snmp_sysname", "snmp_enterprise", "snmp_syscontact", "snmp_syslocation"}},
	"printer_probe":                     {Name: "printer_probe", Mode: "active", Transports: []string{"ipp", "pjl", "http"}, SupportsCredentials: true, ExpectedKeys: []string{"printer_make_model", "printer_uri_supported", "printer_uuid", "printer_state", "printer_command_set"}},
	"camera_probe":                      {Name: "camera_probe", Mode: "active", Transports: []string{"rtsp", "onvif", "http"}, SupportsCredentials: true, ExpectedKeys: []string{"camera_rtsp_server", "camera_onvif_model", "camera_snapshot_realm", "camera_vendor", "camera_stream_path"}},
	"media_device_probe":                {Name: "media_device_probe", Mode: "active", Transports: []string{"http", "https", "rtsp", "adb"}, ExpectedKeys: []string{"airplay_server", "airplay_model", "cast_model", "cast_manufacturer", "media_server_product", "roku_model", "dlna_device_type"}},
	"rdp_service_probe":                 {Name: "rdp_service_probe", Mode: "active", Transports: []string{"rdp"}, ExpectedKeys: []string{"rdp_protocol", "rdp_nla", "rdp_tls", "rdp_cert_subject", "rdp_ntlm_target"}},
	"voip_telemetry_probe":              {Name: "voip_telemetry_probe", Mode: "active", Transports: []string{"sip", "rtp", "stun", "turn"}, ExpectedKeys: []string{"sip_server", "sip_user_agent", "sip_realm", "sip_transport", "stun_software"}},
	"home_api_probe":                    {Name: "home_api_probe", Mode: "active", Transports: []string{"http", "https"}, SupportsCredentials: true, ExpectedKeys: []string{"http_api", "api_status", "api_title", "api_product", "api_version"}},
	"llmnr_responder_analysis":          {Name: "llmnr_responder_analysis", Mode: "active", Transports: []string{"llmnr", "udp/5355"}, ExpectedKeys: []string{"llmnr_name", "llmnr_ip", "llmnr_responder_count", "llmnr_conflict"}},
	"router_gateway_proc_lookup":        {Name: "router_gateway_proc_lookup", Mode: "derived", Transports: []string{"route_table"}, ExpectedKeys: []string{"gateway", "gateway_interface", "gateway_metric", "gateway_family"}},
	"switch_controller_telemetry":       {Name: "switch_controller_telemetry", Mode: "active", Transports: []string{"http", "https", "stun"}, SupportsCredentials: true, ExpectedKeys: []string{"controller_product", "controller_version", "controller_realm", "controller_stun"}},
	"firewall_traffic_profile":          {Name: "firewall_traffic_profile", Mode: "active", Transports: []string{"dns", "http", "https", "ssh"}, SupportsCredentials: true, ExpectedKeys: []string{"dns_version_bind", "firewall_http_title", "firewall_tls_subject", "firewall_ssh_banner"}},
	"flow_netflow_ipfix":                {Name: "flow_netflow_ipfix", Mode: "passive", RequiresPrivilege: true, Transports: []string{"udp/2055", "udp/4739"}, ExpectedKeys: []string{"flow_exporter", "flow_observation_domain", "flow_template_id", "flow_pen", "flow_protocol", "flow_status"}},
	"packet_ttl_os_fingerprint":         {Name: "packet_ttl_os_fingerprint", Mode: "active", Transports: []string{"icmp"}, RequiresPrivilege: true, ExpectedKeys: []string{"ttl", "os_hint", "hop_distance", "icmp_rtt_ms"}},
	"ipv6_ula_prefix_hints":             {Name: "ipv6_ula_prefix_hints", Mode: "derived", Transports: []string{"ipv6"}, ExpectedKeys: []string{"ipv6_ula", "ipv6_ula_prefix", "ipv6_iid_style"}},
	"credentialed_api":                  {Name: "credentialed_api", Mode: "active", Transports: []string{"http", "https"}, SupportsCredentials: true, ExpectedKeys: []string{"credentialed_api", "credentialed_status", "credentialed_product", "credentialed_version"}},
	"router_admin_inventory":            {Name: "router_admin_inventory", Mode: "active", SupportsCredentials: true, ExplicitOnly: true, Transports: []string{"http", "router_admin"}, ExpectedKeys: []string{"router_admin_inventory_status", "router_admin_inventory_reason", "router_admin_connected_devices_path", "router_admin_list_page_title", "router_admin_list_page_sha1", "router_admin_list_page_bytes", "router_admin_detail_path_status", "router_admin_detail_path", "router_admin_detail_path_candidate", "router_admin_device_count", "router_admin_device_name", "router_admin_display_name"}},
	"snmp_trap_event_pull":              {Name: "snmp_trap_event_pull", Mode: "passive", RequiresPrivilege: true, SupportsCredentials: true, Transports: []string{"snmptrap", "udp/162"}, ExpectedKeys: []string{"snmp_trap_enterprise", "snmp_trap_oid", "snmp_trap_uptime", "snmp_trap_source"}},
	"host_event_log_pull":               {Name: "host_event_log_pull", Mode: "derived", SupportsCredentials: true, Transports: []string{"eventlog"}, ExpectedKeys: []string{"host_event", "host_event_source", "host_event_id", "host_event_level", "host_event_timestamp"}},
	"directory_service_correlation":     {Name: "directory_service_correlation", Mode: "derived", SupportsCredentials: true, Transports: []string{"ldap", "ad", "dns"}, ExpectedKeys: []string{"directory_domain", "directory_ou", "directory_site", "directory_controller", "directory_machine_account"}},
	"manual_operator_label_fallback":    {Name: "manual_operator_label_fallback", Mode: "operator", Transports: []string{"filesystem", "api"}, ExpectedKeys: []string{"manual_label", "manual_label_source", "manual_label_expiry", "manual_label_note"}},
	"cross_scan_time_correlation":       {Name: "cross_scan_time_correlation", Mode: "derived", Transports: []string{"history"}, ExpectedKeys: []string{"first_seen", "last_seen", "seen_count", "recurrence_window", "drift_score"}},
	"port_service_correlation":          {Name: "port_service_correlation", Mode: "derived", Transports: []string{"tcp", "udp"}, ExpectedKeys: []string{"ports", "service_hint", "transport", "service_confidence"}},
	"evidence_graph_merger":             {Name: "evidence_graph_merger", Mode: "derived", Transports: []string{"history", "identity"}, ExpectedKeys: []string{"evidence_graph", "evidence_edge", "evidence_weight", "evidence_reason"}},
	"passive_dhcp_fingerprint":          {Name: "passive_dhcp_fingerprint", Mode: "passive", RequiresPrivilege: true, Transports: []string{"dhcp", "pcap", "logs"}, ExpectedKeys: []string{"dhcp_prl", "dhcp_option_order", "dhcp_vendor_class", "dhcp_client_identifier", "dhcp_requested_address", "dhcp_hostname", "dhcp_message_type", "dhcp_fingerprint_status"}},
	"passive_dns_client_profile":        {Name: "passive_dns_client_profile", Mode: "passive", RequiresPrivilege: true, Transports: []string{"dns", "pcap", "resolver_log"}, ExpectedKeys: []string{"dns_query_count", "dns_unique_query_count", "dns_query_category", "dns_query_transport", "dns_reverse_lookup_count", "dns_local_lookup_count", "dns_client_profile_status"}},
	"passive_tls_client_fingerprint":    {Name: "passive_tls_client_fingerprint", Mode: "passive", RequiresPrivilege: true, Transports: []string{"tls", "pcap"}, ExpectedKeys: []string{"tls_client_ja3", "tls_client_version", "tls_client_alpn", "tls_client_sni_category", "tls_client_cipher_order_hash", "tls_client_extension_order_hash", "tls_client_fingerprint_status"}},
	"passive_quic_fingerprint":          {Name: "passive_quic_fingerprint", Mode: "passive", RequiresPrivilege: true, Transports: []string{"quic", "pcap"}, ExpectedKeys: []string{"quic_version", "quic_sni_category", "quic_alpn", "quic_fingerprint_hash", "quic_client_status"}},
	"passive_ipv6_client_profile":       {Name: "passive_ipv6_client_profile", Mode: "passive", RequiresPrivilege: true, Transports: []string{"ipv6", "pcap"}, ExpectedKeys: []string{"ipv6_ndp_role", "ipv6_privacy_address_rotation", "ipv6_slaac_behavior", "ipv6_client_profile_status"}},
	"wifi_client_association_telemetry": {Name: "wifi_client_association_telemetry", Mode: "passive", SupportsCredentials: true, Transports: []string{"syslog", "wifi_controller"}, ExpectedKeys: []string{"wifi_assoc_state", "wifi_assoc_rssi", "wifi_assoc_band", "wifi_assoc_channel", "wifi_assoc_session_duration", "wifi_roam_count", "wifi_client_profile_status"}},
	"resolver_client_profile":           {Name: "resolver_client_profile", Mode: "passive", SupportsCredentials: true, Transports: []string{"resolver_log"}, ExpectedKeys: []string{"resolver_query_count", "resolver_query_category", "resolver_srv_lookup_count", "resolver_local_lookup_count", "resolver_profile_status"}},
	"passive_session_profile":           {Name: "passive_session_profile", Mode: "passive", SupportsCredentials: true, Transports: []string{"firewall_log", "session_table"}, ExpectedKeys: []string{"session_count", "session_protocol_mix", "session_long_lived_count", "session_remote_category", "session_burstiness", "session_profile_status"}},
}

func ResolveStrategies(names []string) []Strategy {
	all := AllStrategies()
	if len(names) == 0 {
		return DefaultStrategies()
	}

	normalize := func(s string) string {
		return strings.ToLower(strings.TrimSpace(s))
	}

	nameToStrategy := make(map[string]Strategy, len(all))
	for _, strat := range all {
		nameToStrategy[normalize(strat.Name())] = strat
	}

	filtered := make([]Strategy, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		n := normalize(name)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		if strat, ok := nameToStrategy[n]; ok {
			filtered = append(filtered, strat)
			seen[n] = struct{}{}
		}
	}
	return filtered
}

func AllStrategies() []Strategy {
	return []Strategy{
		&ArpNeighbor{},
		&MacOuiAndLocalAdmin{},
		NewDHCPV4Options(),
		NewDHCPV6DUID(),
		NewStaticIPLease(),
		&DnsReversePtr{},
		&DnsQueryObservation{},
		&MdnsPassive{},
		&MdnsActive{},
		&SsdpPassive{},
		&SsdpActive{},
		&UpnpDescriptionFetch{},
		&NetbiosLlmnrPassive{},
		&WsdDiscovery{},
		&LldpNeighbors{},
		&CdpControl{},
		&Radius8021xIdentity{},
		&Wireless11Beacon{},
		&PassiveServiceFingerprintPcap{},
		&PassiveTLSHandshake{},
		&PassiveSshBanner{},
		&PassiveHttpMetadata{},
		&PassiveDHCPFingerprint{},
		&PassiveDNSClientProfile{},
		&PassiveTLSClientFingerprint{},
		&PassiveQUICFingerprint{},
		&PassiveIPv6ClientProfile{},
		&WiFiClientAssociationTelemetry{},
		&ResolverClientProfile{},
		&PassiveSessionProfile{},
		&IcmpReachability{},
		NewARPActiveRefresh(),
		&TcpConnectPortMicroset{},
		&HttpHeaderProbe{},
		&HttpFaviconFingerprint{},
		&TlsCertProbe{},
		&SshBannerProbe{},
		&SmbInfoProbe{},
		&SmbNbnsActive{},
		&UpnpServiceControl{},
		&SnmpSystemIdentity{},
		&PrinterProbe{},
		&CameraProbe{},
		&MediaDeviceProbe{},
		&RdpServiceProbe{},
		&VoipTelemetryProbe{},
		&HomeApiProbe{},
		&LlmnrResponderAnalysis{},
		NewRouterGatewayProcLookup(),
		&SwitchControllerTelemetry{},
		&FirewallTrafficProfile{},
		&FlowNetflowIpfix{},
		&PacketTtlOsFingerprint{},
		NewIPv6ULAPrefixHints(),
		&CredentialedAPI{},
		&RouterAdminInventory{},
		&SnmpTrapEventPull{},
		&HostEventLogPull{},
		&DirectoryServiceCorrelation{},
		&ManualOperatorLabelFallback{},
		&CrossScanTimeCorrelation{},
		&PortServiceCorrelation{},
		&EvidenceGraphMerger{},
	}
}

func DefaultStrategies() []Strategy {
	all := AllStrategies()
	filtered := make([]Strategy, 0, len(all))
	for _, strategy := range all {
		if IsExplicitOnlyStrategy(strategy.Name()) {
			continue
		}
		filtered = append(filtered, strategy)
	}
	return filtered
}

func StrategyMetadataForName(name string) (StrategyMetadata, bool) {
	metadata, ok := strategyMetadata[normalizeStrategyName(name)]
	return metadata, ok
}

func IsExplicitOnlyStrategy(name string) bool {
	metadata, ok := StrategyMetadataForName(name)
	return ok && metadata.ExplicitOnly
}

func StrategyMetadataCatalog() []StrategyMetadata {
	out := make([]StrategyMetadata, 0, len(strategyMetadata))
	for _, metadata := range strategyMetadata {
		out = append(out, metadata)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func normalizeStrategyName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
