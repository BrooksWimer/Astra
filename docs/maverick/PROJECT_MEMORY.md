# Astra / Netwise Project Memory

Durable cross-workstream facts, decisions, and conventions. Operator-editable; planning agents read this before each slice.

## 2026-05-05 — Maverick doctrine bootstrap

- Wrote initial Astra/Netwise doctrine on `master`: PROJECT_CONTEXT.md, PROJECT_ROADMAP.md (this file), PROJECT_MEMORY.md, augmented charters for the three durable epics.
- Branch model is the standard Maverick disposable-workstream pattern: `master` is production; epic branches `codex/laptop-wifi-scanner-epic`, `codex/mobile-wifi-scanner-epic`, `codex/router-admin-ingestion-epic` are durable lanes. Workstreams branch from the epic, finish back into the epic, and the epic gets explicitly promoted to `master`.

## Naming rule

- **Astra** in any public-facing artifact (portfolio, marketing, product copy, mobile app store metadata).
- **Netwise** for repo paths, package names, environment variables, and internal Maverick orchestration references.
- The repo lives at `C:\Users\wimer\Desktop\Sentry\netwise` and is referenced as `netwise` in `config/control-plane.shared.json`. The product called Astra _is_ the netwise codebase; no separate Astra repo exists or is planned.

## v1 definition

- Mobile, Wi-Fi integration, and desktop agent all functional, with a hosted backend syncing user data between mobile and desktop.
- App Store submission is **not** required for v1.
- Audience is ordinary home users; not network admins, not security pros.

## Mobile vs desktop role split

- Mobile = acquisition surface. Inviting, simple, useful within iPhone capability constraints.
- Desktop = the "real" scanner. Deeper probing, longer scans, capabilities Apple's local-network entitlement doesn't allow.
- Hosted backend syncs labels across surfaces.

## Vendor-agnostic posture

- Router-admin ingestion is **not** an Xfinity-specific feature. Xfinity at `http://10.0.0.1` is the operator's home gateway and therefore the first test target. The implementation must use a strategy + adapter pattern that generalizes to other vendors (Netgear, TP-Link, ASUS, Ubiquiti, Linksys, etc.).
- Don't hardcode selectors, don't assume a specific markup shape, don't shortcut around the adapter abstraction "just for Xfinity."

## iPhone scanning trajectory

- Long-term goal: hybrid scanning. Bonjour / mDNS first, plus whatever active probing Apple's entitlements allow, plus backend-supplied labels from prior desktop scans.
- Short-term: Bonjour / mDNS only. Document the iOS feasibility boundary explicitly so users (and future planning calls) know why mobile-only labeling isn't as deep as desktop-mode.

## Validation environment

- Primary: operator's home network. This is the floor for "does this work" claims, not the ceiling.
- Anything claiming broader applicability (multi-vendor router admin, accuracy on diverse home networks, label quality on networks the operator hasn't seen) needs evidence beyond the operator's home.
- Lab / synthetic test networks are useful but not authoritative. Real home networks of varied compositions are.

## Privacy posture

- Mobile and desktop scanner data syncs through the hosted backend; this is required for v1 cross-surface story.
- The exact privacy model (what's synced, what's local-only, what's anonymous vs accounted) is undecided as of 2026-05-05. Capture decisions here when made.
- Do not claim privacy properties that aren't enforced. "We don't see your devices" needs the architecture to actually not see them.

## Existing scanner research is durable

- `agent/docs/WIFI_SCANNER_MAP.md`, `WIFI_STRATEGY_CATALOG.md`, `WIFI_DECISION_RUBRIC.md`, `LABELING_IMPROVEMENTS_2026-03.md`, and any future research files in that directory are **durable context**. Planning calls should read them when scoping scanner work; they should not be deleted as part of "cleanup."
- New research notes go in the same directory with the same naming convention (`<TOPIC>_<YYYY-MM>.md`).

## Open questions carried forward

- **Privacy / account model**: anonymous handles vs accounts vs SSO. Decision deferred until M3 (hosted-backend sync) starts.
- **Router-admin vendor priority** (after Xfinity): unknown. Defer until M4 begins; pick based on which router brand a beta tester actually has.
- **iPhone-native scanning realism**: how far can hybrid go before the boundary becomes "you need the desktop agent"? Answered empirically as M5 progresses.
- **App Store readiness**: not yet a question. Becomes one after v1 lands.
