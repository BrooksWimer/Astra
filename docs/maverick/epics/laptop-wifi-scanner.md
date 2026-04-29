# Epic: laptop-wifi-scanner

Owns laptop/desktop LAN scanning through the Go agent, scanner strategy research, labeling quality, and validation reports.

## Goal

Improve local network discovery and labeling quality so Astra can help home users understand what devices are on their network.

## Scope

- Go scanner behavior in `agent/`.
- Strategy comparisons and reports.
- Labeling quality improvements.
- Regression tests and live-run evidence.

## Out Of Scope

- Mobile-only implementation unless it informs scanner feasibility.
- Router-admin authenticated ingestion, which belongs to `router-admin-ingestion`.

## TODO

- Summarize the current best strategy profile and evidence.
- Link canonical evaluation reports.
