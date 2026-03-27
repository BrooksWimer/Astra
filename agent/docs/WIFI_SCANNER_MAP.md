# Wi-Fi Scanner Map

This is the operator-facing map of the current Wi-Fi scanner. It is meant to answer five questions quickly:

1. Where does device discovery actually happen?
2. Where does enrichment happen?
3. Where does labeling happen?
4. Why does a scan take as long as it does?
5. Which file should you read before changing behavior?

## Primary Control Surface

| File | Why it matters |
| --- | --- |
| `cmd/agent/main.go` | Entry point for `experiment`, `evaluate`, `dataset`, `optimize`, and now `catalog`. |
| `internal/scanner/scanner.go` | The live scan pipeline: bootstrap, discovery, enrichment, strategy collection, and repeated relabeling. |
| `internal/strategy/profile.go` | Strategy tiers, fast/medium/full/label_core profiles, and the audit judgments that drive placement. |
| `internal/strategy/registry.go` | Raw strategy metadata: mode, transports, and expected emitted keys. |
| `internal/labeling/labeling.go` | The actual classifier that turns evidence into `device_type`, confidence, and candidate labels. |
| `internal/scanner/experiment.go` | Report builder used to inspect timing, observation yield, and target coverage. |
| `internal/eval/report.go` | Label quality, ablations, calibration, and quality-gate reporting. |
| `internal/optimize/report.go` | Strategy ranking, profile comparison, and value-per-time analysis. |

## Runtime Pipeline

### Stage 0: Control plane

- `cmd/agent/main.go` loads `config.json`.
- `scanner.NewWithStrategyFilter` resolves either:
  - explicit strategy names,
  - the configured profile,
  - or all strategies.

This stage decides **what can run**, not **what the scan finds**.

### Stage 1: Passive runtime bootstrap

- `strategy.StartPassiveRuntime` starts any passive collection window configured in the agent.
- This is contextual support for later strategy collection.

This stage is mostly **context collection**, not direct discovery.

### Stage 2: Baseline device discovery

In `internal/scanner/scanner.go`, the first concrete device rows come from:

- `arp.Table()`
- `arp.Sweep(...)`
- subnet enumeration via `network.EnumerateSubnet(...)`
- the built-in TCP probe sweep on `80`, `443`, and `22`

This is the first major **discovery** stage. If a device never appears here or through multicast discovery, later strategies usually cannot help.

### Stage 3: Multicast discovery and cheap identity enrichment

Still in `scanner.go`, the scanner runs:

- `mdns.Browse(...)`
- `ssdp.Discover(...)`
- `fetchSSDPDescriptions(...)`

This stage does two jobs:

- **discovery**: finds devices that did not appear from ARP or the TCP probe sweep
- **enrichment**: adds mDNS, SSDP, and UPnP identity clues that are often decisive for routers, TVs, printers, and cameras

### Stage 4: Optional explicit port scan

- `portScan(...)` only runs when `enable_port_scan` is true.
- It adds extra open-port evidence and flags risky services such as `445` and `3389`.

This is mostly **enrichment/risk surfacing**, not core discovery.

### Stage 5: Built-in fingerprint enrichment

The scanner then runs two narrow enrichers before the generic strategy layer:

- `enrichFingerprints(...)`
  - HTTP `Server`
  - TLS subject / issuer / SANs
  - SSH banner
- `enrichNetBIOS(...)`
  - NetBIOS names from `nbtstat`

These are **cheap enrichers** that make later labeling easier.

### Stage 6: Strategy observation collection

`collectStrategyObservations(...)` is the main evidence plane.

- Every selected strategy runs against the current target set.
- Each strategy emits structured observations with:
  - `strategy`
  - `key`
  - `value`
  - `details`
- `StrategyRunStat` captures:
  - `strategy`
  - `duration_ms`
  - `emitted_observations`
  - `panicked`

This stage is where most of the **labeling evidence** comes from.

### Stage 7: Repeated relabeling

`recomputeClassification(...)` runs after:

- ARP / probe upserts
- optional port scan updates
- fingerprint enrichers
- NetBIOS enrichment
- strategy observation persistence

Important implication:

- discovery and labeling are interleaved
- you do not need to wait until the very end for labels to change
- moving a strategy earlier or later changes not just runtime, but also when labels can stabilize

## Discovery vs Enrichment vs Labeling

| Area | Main code path | Primary job |
| --- | --- | --- |
| Device discovery | ARP table, ARP sweep, subnet TCP probe, mDNS, SSDP | Create and retain device rows. |
| Identity enrichment | UPnP description fetch, HTTP/TLS/SSH enrichment, NetBIOS, metadata-derived strategies | Add facts to already-discovered devices. |
| Labeling | `recomputeClassification` -> `labeling.ClassifyDevice` | Turn accumulated evidence into category + confidence. |

Practical rule:

- If a change adds devices, it is discovery work.
- If a change adds observations to an existing device, it is enrichment work.
- If a change changes `device_type`, confidence, or candidate labels without adding devices, it is labeling work.

## Why Scan Time Grows

Scan time is the sum of:

1. fixed scanner work
   - ARP/bootstrap
   - multicast discovery
   - built-in probe/enrichment work
2. strategy-phase work
   - every selected strategy runtime
   - especially high-fanout or multi-protocol probes

The fixed work matters, but the strategy phase is where the large profile-to-profile differences appear.

## Current Benchmark Anchor

These are the checked-in live artifacts that are easiest to compare when learning the scanner:

| Artifact | Profile | Duration | Targets | Labeled | Unknown |
| --- | --- | ---: | ---: | ---: | ---: |
| `experiment-live-label-core-20260323-postfix.json` | `label_core` | `125,661 ms` | 18 | 3 | 15 |
| `experiment-live-fast.json` | `fast` | `336,255 ms` | 16 | 1 | 15 |
| `experiment-live-medium.json` | `medium` | `1,026,699 ms` | 14 | 14 | 0 |
| `experiment-live-full.json` | `full` | `2,313,122 ms` | 15 | 3 | 12 |

What this means operationally:

- `label_core` is the best small profile for understanding the current label pipeline.
- `fast` is broader than `label_core`, but still speed-oriented.
- `medium` is where the scanner starts doing serious second-wave enrichment.
- `full` is the evidence-maximizing reference path, not the first place to start learning.

## Learning Commands

Use one benchmark network and compare against the same baseline artifacts.

```powershell
# Run one live profile and inspect timing / yield
go run ./cmd/agent experiment --profile label_core --out experiment-current.json

# Evaluate labels and quality from one or more corpus inputs
go run ./cmd/agent evaluate --inputs experiment-current.json --out evaluation-current.json

# Compare profiles and rank strategy value per time
go run ./cmd/agent optimize --inputs experiment-current.json --report experiment-current.json --out optimization-current.json

# Export the current operator catalog straight from the codebase
go run ./cmd/agent catalog --format json
```

## Questions This Map Should Let You Answer

- Why did the scan take this long?
  - Look at `scan_duration_ms`, then `strategy_reports[].duration_ms`.
- Which stage actually found this device?
  - Check whether the device first appeared from ARP / probe / mDNS / SSDP before strategy observations.
- Which strategy changed the label?
  - Check the device observations plus `label_state` candidates and reasons.
- What happens if I move a strategy from fast path to second wave?
  - Compare profile output with `optimize`, then validate live with `experiment`.
