# Wi-Fi Strategy Catalog Guide

This guide is the human front-end for the exact machine-readable strategy catalog.

## Source of Truth

Run this from `agent/`:

```powershell
go run ./cmd/agent catalog --format json
```

The export gives you one row-like JSON object per strategy with:

- `name`
- `purpose`
- `mode`
- `execution_class`
- `speed_cost`
- `discovery_value`
- `labeling_value`
- `default_placement`
- `likely_inputs`
- `likely_outputs`
- `included_in_profiles`

That export is the exact answer to:

- what a strategy does
- what it costs
- what it emits
- which profiles include it
- where the current audit thinks it belongs

## How To Read The Named Profiles

- `label_core`
  - smallest real profile
  - best anchor for understanding current label behavior
- `fast`
  - first-pass discovery and attribution profile
  - meant to be the operator’s speed-oriented baseline
- `medium`
  - fast plus second-wave enrichers and `media_device_probe`
  - best profile for understanding what the scanner does once it is allowed to spend more time
- `full`
  - all 63 registered strategies in registry order
  - use as the evidence-maximizing reference path

## Exact Profile Membership

### `label_core` (7)

```text
arp_neighbor
arp_active_refresh
mac_oui_and_localadmin
ssdp_active
upnp_description_fetch
media_device_quick_probe
manual_operator_label_fallback
```

### `fast` (11)

```text
arp_neighbor
mac_oui_and_localadmin
ssdp_passive
ssdp_active
upnp_description_fetch
netbios_llmnr_passive
icmp_reachability
arp_active_refresh
router_gateway_proc_lookup
manual_operator_label_fallback
port_service_correlation
```

### `medium` (42)

```text
arp_neighbor
mac_oui_and_localadmin
dhcpv4_options
dhcpv6_duid
static_ip_lease
dns_ptr_reverse
dns_query_observation
mdns_passive
mdns_active
ssdp_passive
ssdp_active
upnp_description_fetch
netbios_llmnr_passive
wsd_discovery
passive_service_fingerprint_pcap
passive_tls_handshake
passive_http_metadata
passive_dhcp_fingerprint
passive_dns_client_profile
passive_tls_client_fingerprint
passive_quic_fingerprint
wifi_client_association_telemetry
resolver_client_profile
passive_session_profile
icmp_reachability
arp_active_refresh
tcp_connect_microset
http_header_probe
http_favicon_fingerprint
tls_cert_probe
ssh_banner_probe
smb_info_probe
smb_nbns_active
media_device_quick_probe
rdp_service_probe
llmnr_responder_analysis
router_gateway_proc_lookup
packet_ttl_os_fingerprint
directory_service_correlation
manual_operator_label_fallback
port_service_correlation
media_device_probe
```

### `full` (63)

```text
arp_neighbor
mac_oui_and_localadmin
dhcpv4_options
dhcpv6_duid
static_ip_lease
dns_ptr_reverse
dns_query_observation
mdns_passive
mdns_active
ssdp_passive
ssdp_active
upnp_description_fetch
netbios_llmnr_passive
wsd_discovery
lldp_neighbors
cdp_control
radius_8021x_identity
wireless_11_beacon
passive_service_fingerprint_pcap
passive_tls_handshake
passive_ssh_banner
passive_http_metadata
passive_dhcp_fingerprint
passive_dns_client_profile
passive_tls_client_fingerprint
passive_quic_fingerprint
passive_ipv6_client_profile
wifi_client_association_telemetry
resolver_client_profile
passive_session_profile
icmp_reachability
arp_active_refresh
tcp_connect_microset
http_header_probe
http_favicon_fingerprint
tls_cert_probe
ssh_banner_probe
smb_info_probe
smb_nbns_active
upnp_service_control
snmp_system_identity
printer_probe
camera_probe
media_device_probe
media_device_quick_probe
rdp_service_probe
voip_telemetry_probe
home_api_probe
llmnr_responder_analysis
router_gateway_proc_lookup
switch_controller_telemetry
firewall_traffic_profile
flow_netflow_ipfix
packet_ttl_os_fingerprint
ipv6_ula_prefix_hints
credentialed_api
snmp_trap_event_pull
host_event_log_pull
directory_service_correlation
manual_operator_label_fallback
cross_scan_time_correlation
port_service_correlation
evidence_graph_merger
```

## Quick Placement View

Use `default_placement` from the catalog as the current repo judgment, not as unquestionable truth:

- `fast_path`
  - low-cost strategies that should compete for first-pass inclusion
- `second_wave`
  - useful enrichers that are normally too broad or too slow for the very first pass
- `expensive`
  - high-value specialists that should usually be opt-in or target-triggered
- `contextual`
  - useful supporting context, but not core first-pass identifiers
- `noise`
  - weak attribution or low operator value for default use

## Fast Ways To Inspect One Strategy

```powershell
# Show one strategy from the live code catalog
$catalog = go run ./cmd/agent catalog --format json | ConvertFrom-Json
$catalog.strategies | Where-Object { $_.name -eq 'upnp_description_fetch' } | ConvertTo-Json -Depth 6

# Compare one strategy’s timing/yield from an experiment report
$report = Get-Content .\experiment-live-label-core-20260323-postfix.json | ConvertFrom-Json
$report.strategy_reports | Where-Object { $_.strategy -eq 'upnp_description_fetch' } | Format-List
```

## Operator Reading Order

When you are learning or reviewing changes, use this order:

1. `label_core`
2. `fast`
3. `medium`
4. `full`

And for strategy-by-strategy review, start here:

1. `arp_neighbor`
2. `arp_active_refresh`
3. `ssdp_active`
4. `upnp_description_fetch`
5. `media_device_quick_probe`
6. `port_service_correlation`
7. `netbios_llmnr_passive`

That order keeps you focused on the strategies that shape first-pass practical results before you widen into the expensive tail.
