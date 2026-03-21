# Fast Scan Optimization Notes

Date: 2026-03-21

The original request referenced 54 strategies, but the current checkout now registers 62 strategies in `internal/strategy/registry.go`. The recommendations below are based on the code and artifacts that were present on 2026-03-21.

## Profiles

`fast`
- `arp_neighbor`
- `mac_oui_and_localadmin`
- `ssdp_passive`
- `ssdp_active`
- `upnp_description_fetch`
- `netbios_llmnr_passive`
- `icmp_reachability`
- `arp_active_refresh`
- `router_gateway_proc_lookup`
- `manual_operator_label_fallback`
- `port_service_correlation`

`medium`
- Includes `fast`
- Adds targeted enrichers such as `mdns_active`, `dns_ptr_reverse`, `tls_cert_probe`, `ssh_banner_probe`, `smb_info_probe`, `rdp_service_probe`, `llmnr_responder_analysis`
- Adds the one expensive probe that materially preserved TV labeling in the scoped replay: `media_device_probe`
- Also keeps the new passive client-profile strategies in this checkout so the profile can surface more client-device hypotheses

`full`
- All registered strategies remain available and unchanged

## Tiering Summary

Fast path
- `arp_neighbor`
- `arp_active_refresh`
- `mac_oui_and_localadmin`
- `ssdp_active`
- `ssdp_passive`
- `upnp_description_fetch`
- `netbios_llmnr_passive`
- `icmp_reachability`
- `port_service_correlation`
- `router_gateway_proc_lookup`
- `manual_operator_label_fallback`

Second wave
- `mdns_active`
- `dns_ptr_reverse`
- `dns_query_observation`
- `http_header_probe`
- `http_favicon_fingerprint`
- `tls_cert_probe`
- `ssh_banner_probe`
- `smb_info_probe`
- `smb_nbns_active`
- `rdp_service_probe`
- `wsd_discovery`
- `llmnr_responder_analysis`
- `directory_service_correlation`
- Passive client-profile strategies when capture/controller data exists

Useful but expensive
- `media_device_probe`
- `camera_probe`
- `printer_probe`
- `snmp_system_identity`
- `switch_controller_telemetry`
- `firewall_traffic_profile`
- `home_api_probe`
- `voip_telemetry_probe`
- `upnp_service_control`
- `credentialed_api`

Mostly contextual or noise-prone for a fast scan
- `wireless_11_beacon`
- `host_event_log_pull`
- `cross_scan_time_correlation`
- `evidence_graph_merger`
- `lldp_neighbors`
- `cdp_control`
- `flow_netflow_ipfix`
- `snmp_trap_event_pull`
- `ipv6_ula_prefix_hints`

## Live Results

Full
- `experiment-live-full.json`
- 38m 33s
- 15 targets with evidence
- 715 real-data observations
- Labels: 1 router, 2 TVs, 12 unknown

Fast
- `experiment-live-fast.json`
- 5m 36s
- 16 targets with evidence
- 342 real-data observations
- Labels: 1 router, 15 unknown
- Compared with full on shared devices, both TVs degraded out of their full-profile labels

Medium
- `experiment-live-medium.json`
- 17m 07s
- 14 targets with evidence
- 628 real-data observations
- Labels: 1 router, 2 TVs, 11 IoT
- Compared with full on shared devices, TV labels were preserved, but many previously unknown devices were promoted to `iot`

## Recommendation

Default fast profile
- Use `fast` as the default speed-optimized profile
- It preserves the router path, keeps the scan under 6 minutes on this network, and avoids the heavy probes that dominate full-scan runtime

When to use `medium`
- Use `medium` as an opt-in follow-up when you need better TV/media coverage
- Treat its extra client/device labels carefully on this checkout, because the passive/client-profile strategies can aggressively convert unknowns into `iot`

What not to change
- Keep `full` intact as the evidence-maximizing path
- Do not use `medium` as an automatic replacement for `full` until the new passive client-profile strategies have ground-truth validation
