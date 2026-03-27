# Netwise Agent

Go agent: LAN discovery, REST API on port 7777, mDNS advertisement.

## Build & run

```bash
cd agent
go build -o agent.exe ./cmd/agent   # or: make build
go run ./cmd/agent                  # or: make run
```

Run from the `agent/` directory so `config.json` is found.

## Tests

Run all tests:

```bash
cd agent
go test ./...
```

Run tests for a specific package:

```bash
go test ./internal/network/...
go test ./internal/arp/...
go test ./internal/classify/...
```

- **network**: mask/broadcast formatting, subnet enumeration
- **arp**: Windows/darwin ARP output parsing (platform-specific tests)
- **classify**: rule-based device classification (printer, tv, router, unknown)

## Config

`config.json`:

| Field | Default | Description |
|-------|---------|-------------|
| `enable_port_scan` | false | If true, probe ports after discovery |
| `ports_to_check` | [22,80,443,445,554,631,3389,8009,1900] | Ports for optional probe |
| `scan_timeout_seconds` | 20 | Max scan duration |
| `scan_mode` | "standard" | quick (2-5s), standard (10-20s), deep (30-60s) |
| `max_probe_ips` | 0 | Cap on IPs to probe (0 = no limit) |
| `large_subnet_throttle` | true | When true, cap probes on /16 or larger (uses max_probe_ips) |

## Operator Docs

If the current goal is understanding and directing the scanner rather than expanding it, start here:

- `docs/WIFI_SCANNER_MAP.md`
- `docs/WIFI_STRATEGY_CATALOG.md`
- `docs/WIFI_DECISION_RUBRIC.md`

The machine-readable strategy catalog can be exported from the live codebase:

```bash
go run ./cmd/agent catalog --format json
```

## API (local testing)

With the agent running:

```powershell
# Health
Invoke-RestMethod -Uri "http://127.0.0.1:7777/health"

# Network facts (interface, CIDR, gateway, MAC, large_subnet)
Invoke-RestMethod -Uri "http://127.0.0.1:7777/info"

# Start scan
$r = Invoke-RestMethod -Uri "http://127.0.0.1:7777/scan/start" -Method POST
$scanId = $r.scan_id

# After a few seconds: scan result and devices
Start-Sleep -Seconds 8
Invoke-RestMethod -Uri "http://127.0.0.1:7777/scan/$scanId"
Invoke-RestMethod -Uri "http://127.0.0.1:7777/devices"
```

## Discovery pipeline

1. **Passive**: Read OS ARP/neighbor table (Windows: `arp -a`, macOS: `arp -an`, Linux: `/proc/net/arp`).
2. **Active**: TCP connect probe to common ports (80, 443, 22) on subnet IPs; rate-limited and throttled on large subnets.
3. **Enrichment**: OUI vendor lookup, reverse DNS hostname.
4. **Classification**: Rule-based (vendor, hostname, mDNS/SSDP services, ports) → device_type, confidence, reasons.

Output includes `sources_seen` (arp, tcp_probe) and `classification_reasons` per device.
