# Deep Fast-Scan Context

## Mission

Create a sub-2-minute fast scan profile that preserves the 4 best known labels on this network, while keeping the full scanner intact.

Hard constraints:

- Do not weaken or remove the full scanner.
- Do not rewrite the project around a new architecture.
- Treat the fast path as an optimization profile, not a replacement.
- Favor practical labeling quality over raw observation count.

## Repo State

- Repo root: `C:\Users\wimer\Desktop\Sentry\netwise`
- Branch: `codex/fast-scan-optimization`
- Current fast profile under test: `label_core`

Relevant code files:

- `internal/strategy/profile.go`
- `internal/strategy/media_device_quick_probe.go`
- `internal/strategy/upnp_description_fetch.go`
- `internal/labeling/labeling.go`
- `internal/scanner/scanner.go`
- `internal/scanner/experiment.go`
- `internal/config/config.go`
- `FAST_SCAN_NOTES.md`

## Best Labeling Baselines

### 1. Fresh live full sweep

Artifact: `experiment-passive-full-sweep.json`

- Source: `live`
- Strategy profile: `full`
- Duration: `2,267,562 ms` (~37m 48s)
- Devices: `13`
- Labeled: `4`
- Unknown: `9`

Labeled devices:

- Camera `8c:e7:48:43:e3:1e`
  - Evidence: `SSDP server header: Linux/3.0.8, UPnP/1.0, Portable SDK for UPnP devices/1.4.7; vendor/hostname: camera-like; port:554`
- TV `ae:71:8a:0b:80:59`
  - Evidence: `port:7000; media:airtunes/940.21.1; port:1900`
- TV `74:e2:0c:14:32:51`
  - Evidence: `port:8009; port:1900`
- Router `c8:c6:fe:07:fe:92`
  - Evidence: `SSDP router/gateway signatures and eero server header`

### 2. Historical strong baseline

Artifact: `experiment-deepened-full-sweep-scoped-v3.json`

- Source: `live`
- Duration: `1,697,213 ms` (~28m 17s)
- Devices: `10`
- Labeled: `4`
- Unknown: `6`

This historical baseline has the same 4 key labels:

- camera
- router
- tv
- tv

## Fast-Path Runs Worth Comparing

### 3. Same-day `label_core` before fixes

Artifact: `experiment-live-label-core-20260323-context.json`

- Source: `live`
- Strategy profile: `label_core`
- Duration: `122,637 ms` (~2m 03s)
- Devices: `17`
- Labeled: `3`
- Unknown: `14`

Preserved:

- router
- 2 TVs

Lost:

- camera `8c:e7:48:43:e3:1e`

Important failure details:

- `upnp_description_fetch` failed for the camera with:
  - `proxyconnect tcp: dial tcp 127.0.0.1:9`
- `media_device_quick_probe` saw:
  - `ports=554`
  - `rtsp_status=real_data`
- But the camera still ended as `unknown`

### 4. Same-day `label_core` after local fixes

Artifact: `experiment-live-label-core-20260323-postfix.json`

- Source: `live`
- Strategy profile: `label_core`
- Duration: `125,661 ms` (~2m 06s)
- Devices: `18`
- Labeled: `3`
- Unknown: `15`

Preserved:

- router
- 2 TVs

Still lost:

- camera `8c:e7:48:43:e3:1e`

What improved:

- `upnp_description_fetch` now succeeds for the camera
- `media_device_quick_probe` now contributes `port:554` camera evidence

What still fails:

- Even with successful UPnP and RTSP 554, the camera remains `unknown`
- Post-fix camera label state:
  - top candidate: `camera`
  - calibrated confidence: `0.09785714285714286`
  - evidence summary: `port:554`

Interpretation:

- Current fast-path labeling is not turning the camera's UPnP values into camera confidence
- `upnp_friendly_name=SWANN 192.168.4.20`
- `upnp_manufacturer=SWANN`
- `upnp_model_name=SWANN DVR8-1550`
- `upnp_device_type=urn:schemas-upnp-org:device:EmbeddedNetDevice:1`
- These do not currently produce enough camera score in `label_core`

## Important Concrete Findings

### A. Proxy-related collection bug existed

Current shell environment includes:

- `HTTP_PROXY=http://127.0.0.1:9`
- `HTTPS_PROXY=http://127.0.0.1:9`
- `ALL_PROXY=http://127.0.0.1:9`
- `NO_PROXY=localhost,127.0.0.1,::1`

Observed impact:

- `upnp_description_fetch` was using a default `http.Client`
- That caused local LAN UPnP fetches to route through the dead proxy
- Result: camera UPnP fetch failed in fast-path runs even though the device was reachable

Local patch already applied:

- `internal/strategy/upnp_description_fetch.go`
- UPnP fetches now bypass proxy env vars

### B. `media_device_quick_probe` camera scoring gap existed

Observed impact:

- Quick probe emitted `ports=554`
- Labeling path for `media_device_quick_probe` handled `ports` inside a media-specific switch
- That branch only scored TV ports, so `554` was swallowed before generic port scoring

Local patch already applied:

- `internal/labeling/labeling.go`
- `media_device_quick_probe` `ports=554` now adds camera score

### C. Camera still does not recover after those fixes

This suggests the remaining problem is not just transport or RTSP port collection.

Most likely remaining causes:

- UPnP values like `SWANN`, `DVR8-1550`, and `EmbeddedNetDevice` are not mapped strongly enough to camera/NVR
- `upnp_friendly_name` is not being promoted into device hostname in this fast path
- Fast-path camera heuristics may need either:
  - broader UPnP vendor/model lexicon
  - a small camera-specific second-wave strategy
  - or cheaper derived attribution from the existing UPnP metadata

## High-Value Strategy Timing Facts

From `experiment-passive-full-sweep.json`:

- `media_device_probe`
  - `391,159 ms`
  - `6` real-data observations
  - `3` targets hit
- `snmp_system_identity`
  - `281,150 ms`
  - `0` real-data observations
- `switch_controller_telemetry`
  - `245,916 ms`
  - `0` real-data observations
- `camera_probe`
  - `230,652 ms`
  - `2` real-data observations
  - `1` target hit
- `home_api_probe`
  - `187,322 ms`
  - `0` real-data observations
- `tcp_connect_microset`
  - `137,862 ms`
  - `3` real-data observations
  - `3` targets hit
- `port_service_correlation`
  - `115,267 ms`
  - `45` real-data observations
  - `13` targets hit
- `netbios_llmnr_passive`
  - `54,687 ms`
  - `44` real-data observations
  - `13` targets hit

From `experiment-live-label-core-20260323-postfix.json`:

- `media_device_quick_probe`
  - `61,057 ms`
  - `9` real-data observations
  - `3` targets hit
- `arp_active_refresh`
  - `4,015 ms`
  - `85` real-data observations
- `arp_neighbor`
  - `56 ms`
  - `68` real-data observations
- `upnp_description_fetch`
  - trivial runtime in report, but now `46` observations total

## Optimizer / Replay Context

Artifact: `optimization-report-scoped-v3-current.json`

Important points:

- Baseline full profile on scoped-v3: `4` labeled
- `fast` profile: `2` labeled, loses both TVs
- `medium` profile: `4` labeled, preserves all labels on replay
- Estimated phase budgets from that report are replay/model-based, not wall-clock live proof

Important caveat:

- `internal/scanner/experiment.go`
- `FilterDevicesForStrategySubset` preserves some derived fields during corpus replay
- That makes replay useful for dependency tracing, but optimistic compared with live stripped-down collection

## Suggested Questions For A Deeper Agent

1. Which signals are truly label-critical for the 4 labeled devices, and which full-scan strategies are just expensive breadth?
2. Why does the camera still fail under `label_core` even after UPnP fetch recovery and `port:554` scoring?
3. Should fast-path camera recovery come from:
   - better UPnP parsing and vendor/model heuristics,
   - cheap hostname promotion from `upnp_friendly_name`,
   - a tiny camera-only second-wave strategy,
   - or a slimmed-down `port_service_correlation`/`tcp_connect_microset` reintroduction?
4. Is there a better fast profile than current `label_core` that stays under 2 minutes while preserving all 4 labels?
5. Which expensive strategies are clearly dominated and can be safely deferred to an optional second phase?

## Best Artifact Set To Read First

- `experiment-passive-full-sweep.json`
- `evaluation-report-passive-full-sweep.json`
- `labeling-dataset-passive-full-sweep.json`
- `experiment-deepened-full-sweep-scoped-v3.json`
- `optimization-report-scoped-v3-current.json`
- `experiment-live-label-core-20260323-context.json`
- `experiment-live-label-core-20260323-postfix.json`
- `internal/strategy/profile.go`
- `internal/strategy/media_device_quick_probe.go`
- `internal/strategy/upnp_description_fetch.go`
- `internal/labeling/labeling.go`
- `internal/scanner/experiment.go`
