# Astra / Netwise Project Context

**Astra** is the public-facing product name. **Netwise** is the internal repo and config name. Use Astra in any artifact that leaves the operator's machine (portfolio, marketing, product copy). Use Netwise only in repo paths, package names, and Maverick orchestration references.

## Product Identity

Astra is a home-network intelligence app for **ordinary home users** who want to discover, label, and understand the devices on their Wi-Fi/LAN without being networking experts. The audience is not network admins, not security professionals, not power users — it is people who want to know "what is the thing on my network called Espressif-7c4a3" without having to learn what an OUI lookup is.

The bar for "useful" is the human-readable label, not the scan technique. Scanner sophistication is **product support**, not the product itself.

## System Shape

- `agent/` — Go LAN scanner. Strategy system, scanner CLI, reports, scanner research. The "real" scanner: more capable than what an iPhone can do natively.
- `mobile/` — Expo / React Native client. The acquisition surface — what new users meet first.
- `server/` — Node / Express advice and assistant APIs. Hosted backend for syncing mobile + desktop user data.
- `shared/` — TypeScript types and schemas shared between mobile and server.
- `agent/docs/` — durable scanner research and labeling notes (`WIFI_SCANNER_MAP.md`, `WIFI_STRATEGY_CATALOG.md`, `WIFI_DECISION_RUBRIC.md`, `LABELING_IMPROVEMENTS_2026-03.md`). These are the operator's accumulated thinking; planning agents should read them when scoping scanner work.

## Mobile vs desktop role

- **Mobile** is acquisition. It's how new users meet Astra. It must be inviting, simple, and produce useful labels even with iPhone's capability constraints.
- **Desktop** is the "real" scanner. Once a user is on board, the desktop agent does the deep work — labeling that needs broader probing, longer scans, or capabilities Apple's local-network entitlements don't allow.
- **Both surfaces share user data via the hosted backend.** Mobile-only and desktop-only flows still work, but the cross-device sync is what makes "I scanned at home, now I'm at the office and the labels followed me" work.

## Epics (durable lanes)

- `laptop-wifi-scanner` — Go scanner behavior, strategy comparisons, labeling quality, regression evidence on real home networks.
- `mobile-wifi-scanner` — Expo app, mobile UX, phone-to-agent flows, iPhone-only feasibility.
- `router-admin-ingestion` — authenticated router-admin data extraction. **Vendor-agnostic by design**; Xfinity at `http://10.0.0.1` is the first test target because it's what the operator has, not because the product is Xfinity-specific.

## Planning Rules

- **Use Astra in public-facing artifacts.** Repo paths, internal config, and orchestration references stay Netwise.
- **Treat scanner research as product support, not product identity.** A user doesn't care which mDNS strategy ranked highest in a benchmark; they care what their printer is called.
- **Don't overclaim accuracy without evidence.** Labeling quality claims need a test report, a labeling regression, or a live-run capture.
- **Vendor-agnostic for router admin.** No hardcoded Xfinity selectors that would break on a Netgear UI. Strategy + adapter pattern.
- **Validation on operator's home network is the floor, not the ceiling.** Diversify network mixes when claims expand beyond "works at home."

## Cross-references

- [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md) — milestones, v1 definition, priority order.
- [`PROJECT_MEMORY.md`](PROJECT_MEMORY.md) — durable decisions, naming rules, hardware/network targets.
- [`epics/laptop-wifi-scanner.md`](epics/laptop-wifi-scanner.md), [`epics/mobile-wifi-scanner.md`](epics/mobile-wifi-scanner.md), [`epics/router-admin-ingestion.md`](epics/router-admin-ingestion.md) — durable lane charters.
- [`agent/docs/`](../../agent/docs/) — accumulated scanner research and labeling notes.
- [`AGENTS.md`](../../AGENTS.md) — orchestration doctrine and verification baseline.
