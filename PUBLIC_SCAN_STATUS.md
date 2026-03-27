# Public Scan Status

This is a public-facing summary of the scanner's current benchmark state.

It is intentionally limited to aggregate results. It does not include raw LAN identifiers, hostnames, IP addresses, or MAC addresses.

## Scope

- Date range of the referenced artifacts: 2026-03-21 to 2026-03-23
- Benchmark shape: one real local network used as a repeatable comparison point
- Interpretation: these numbers are useful for direction-setting, not as universal claims about all networks

## Current Benchmark Snapshot

| Profile | Duration | Targets | Labeled | Unknown |
| --- | ---: | ---: | ---: | ---: |
| `label_core` | `125,661 ms` | 18 | 3 | 15 |
| `fast` | `336,255 ms` | 16 | 1 | 15 |
| `medium` | `1,026,699 ms` | 14 | 14 | 0 |
| `full` | `2,313,122 ms` | 15 | 3 | 12 |

## What The Snapshot Suggests

- `label_core` is the smallest useful benchmark for studying the current labeling pipeline.
- `fast` is much quicker than `full`, but it loses important media-device labeling on this benchmark.
- `medium` preserves more useful labels than `fast` on this benchmark, but it still needs careful validation because it can over-promote unknown devices into broad categories like `iot`.
- `full` remains the evidence-maximizing reference path, not the default path you would choose for speed.

## Publicly Shareable Takeaways

- The scanner can already discover a meaningful set of real LAN devices on a live network.
- Runtime is still a major tradeoff. The gap between the faster profiles and the full profile is measured in tens of minutes versus minutes.
- Label quality is uneven. Router and TV/media paths are stronger than the long tail of generic home-network devices.
- Profile design matters as much as raw strategy count. More strategies do not automatically produce better practical results.

## Recommended Reading

- `RESEARCH_BRIEF.md`
- `agent/docs/WIFI_SCANNER_MAP.md`
- `agent/docs/WIFI_STRATEGY_CATALOG.md`
- `agent/docs/WIFI_DECISION_RUBRIC.md`

## Source Artifacts

This summary was derived from checked-in aggregate artifacts and notes, especially:

- `agent/FAST_SCAN_NOTES.md`
- `agent/docs/WIFI_SCANNER_MAP.md`
- `agent/optimization-report-live.json`
- `agent/optimization-report-scoped-v3.json`
