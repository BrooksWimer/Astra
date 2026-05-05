# Epic: router-admin-ingestion

_Read [`../PROJECT_CONTEXT.md`](../PROJECT_CONTEXT.md) and [`../PROJECT_ROADMAP.md`](../PROJECT_ROADMAP.md) before starting a slice. Coordinate with the existing scanner research in [`agent/docs/`](../../../agent/docs/) — router-admin data complements LAN scanner data and should be merged into the same labeled inventory._

## Goal

Let users authenticate Astra against their router's admin UI and pull a richer device inventory than LAN scanning alone produces (DHCP table with hostnames, signal strength per device, parental-controls metadata, port-forward map, etc.). **Vendor-agnostic by design** — Xfinity at `http://10.0.0.1` is the operator's home gateway and therefore the first test target, but the implementation pattern must generalize to Netgear, TP-Link, ASUS, Ubiquiti, Linksys, and beyond.

## In scope

- Credential entry UX in the mobile and/or desktop client.
- Secure credential handling (storage, transport, blast-radius if compromised).
- Authentication flow against router admin UIs.
- Router-UI navigation and data extraction via a strategy + adapter pattern.
- Xfinity at `http://10.0.0.1` as the first live target.
- Durable router-specific discovery notes (which selectors, which auth quirks, which inventory fields each vendor exposes).
- Cross-cutting integration: router-admin labels merged with LAN scanner labels into a single device inventory.

## Out of scope

- LAN scanner technique research — belongs in [`laptop-wifi-scanner`](laptop-wifi-scanner.md). This epic _consumes_ scanner data when merging inventories but does not advance the scanner itself.
- Router firmware vulnerability research / pentesting. Astra reads what the user is authorized to read; it does not exploit.
- Router configuration changes (firewall rules, port forwards, DHCP edits). Read-only ingestion only — write actions are a separate, very deliberate future epic if ever undertaken.
- Carrier-grade NAT / hosted gateway scenarios where the user doesn't have admin access at all. Document the limitation; don't try to work around it.

## Planning guidance

- **Vendor-agnostic from slice 1.** Even if the only working extraction is Xfinity, the code structure must be a strategy + adapter — not a Xfinity-specific scraper with a "we'll generalize later" comment. Generalizing later never happens.
- **No hardcoded selectors leaking into orchestration text.** Vendor-specific markup, navigation flows, and naming conventions live in repo-owned product docs (under `agent/docs/router-admin/`), not in Maverick dispatch transcripts.
- **Credentials are a real attack surface.** Treat them with the security-review skill (see `.agents/skills/security-review/`). No credential logging. No plaintext-on-disk caches. Document the threat model explicitly before implementation.
- **Read-only initially.** Even when the router UI exposes write operations, this epic does not touch them. A future epic might.
- **Test on the operator's home network first.** Xfinity at `10.0.0.1` is the floor; "works on Netgear too" is a future slice with its own validation evidence.
- **Adaptable strategy is the deliverable, not "an Xfinity scraper."** The success signal is "adding a second vendor takes days, not weeks." If a slice writes a vendor-specific fast path that doesn't fit the adapter pattern, that's a regression to flag.

## Open questions deferred

- Vendor priority order after Xfinity (Netgear / TP-Link / ASUS / Ubiquiti / Linksys / others) — answered when M4 begins, based on which router a beta tester actually has.
- Whether desktop, mobile, or both surfaces own the credential entry flow.
- Whether to support hosted-router-management UIs (some vendors have moved to cloud-hosted admin UIs). Likely yes eventually; out of scope for v1.

## Success criteria for M4

(See [`../PROJECT_ROADMAP.md`](../PROJECT_ROADMAP.md) M4 for the canonical statement.)

The operator authenticates Astra against their Xfinity gateway, gets a richer device inventory than LAN scanning alone produces, and the implementation pattern is concrete enough that adding a second vendor is days, not weeks.
