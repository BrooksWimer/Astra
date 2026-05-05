# Epic: laptop-wifi-scanner

_Read [`../PROJECT_CONTEXT.md`](../PROJECT_CONTEXT.md) and [`../PROJECT_ROADMAP.md`](../PROJECT_ROADMAP.md) before starting a slice. The accumulated scanner research lives in [`agent/docs/`](../../../agent/docs/) — `WIFI_SCANNER_MAP.md`, `WIFI_STRATEGY_CATALOG.md`, `WIFI_DECISION_RUBRIC.md`, `LABELING_IMPROVEMENTS_2026-03.md`. That research is durable context for every slice in this lane._

## Goal

Make the Go LAN scanner produce **human-readable labels** that an ordinary home user recognizes, on the operator's home network and on networks the operator has never seen. The scanner is the "real" Astra scanner — deeper probing, longer scans, capabilities iPhone doesn't allow — and its label quality is the floor for the whole product.

## In scope

- Scanner behavior in `agent/` (Go).
- Strategy comparisons and ranking (mDNS, ARP, SSDP, NetBIOS, vendor lookup, active probing, etc.).
- Labeling quality: confidence thresholds, fallback labels, "show as unknown" UX.
- Validation reports and live-run evidence.
- Regression tests with captures from real home networks.

## Out of scope

- Mobile-only scanning paths — those belong in [`mobile-wifi-scanner`](mobile-wifi-scanner.md). Scanner work that informs mobile feasibility (e.g. "what's the Bonjour ceiling?") is fine here as long as the deliverable is desktop-shipping.
- Authenticated router-admin ingestion — belongs in [`router-admin-ingestion`](router-admin-ingestion.md).
- Scanner research as an end in itself. Research must serve a labeling-quality outcome.

## Planning guidance

- **Labels first, technique second.** A new strategy that improves recall by 5% but doesn't move the user-readable-label rate is not a useful slice.
- **Evidence-backed claims only.** Any "this is better than that" claim needs a labeling regression or a live-run capture. The accumulated research files are the existing baseline; new claims update them rather than discarding them.
- **Performance budget.** First-scan latency on a typical home network is a user-felt concern. Optimizations that trade scan depth for speed need explicit operator sign-off.
- **Cross-surface awareness.** When desktop scanner output is changing in ways that affect labels the mobile app shows, coordinate with [`mobile-wifi-scanner`](mobile-wifi-scanner.md). The hosted-backend sync schema lives between them.
- **Update the research files in `agent/docs/`** when a slice produces new strategy data, decision-rubric updates, or labeling-improvement notes. Don't bury the findings in a slice transcript.

## Success criteria for the M1 milestone

(See [`../PROJECT_ROADMAP.md`](../PROJECT_ROADMAP.md) M1 for the canonical statement.)

A scan of the operator's home network produces human-readable labels for at least 80% of the devices the operator can identify by sight, with recognized confidence levels (high / medium / "show as unknown") for the rest.
