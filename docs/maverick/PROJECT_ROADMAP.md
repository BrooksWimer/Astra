# Astra / Netwise Project Roadmap

The Maverick-canonical milestone view. Each milestone has a success signal and a primary epic. Used by the Maverick planning agent to ground each slice in the right lane.

## North star

**Astra v1 ships when mobile, Wi-Fi integration, and the desktop agent are all functional and synced through a hosted backend** — and an ordinary home user can install Astra, scan their network, and get useful labels on the things they own without operator coaching. App Store availability is **not** required for v1; "all three surfaces working in the operator's hand" is the bar.

Priority order across milestones is value-per-effort for an ordinary home user, not technical depth.

---

## M1 — Desktop scanner reaches "useful labels on a real home network"

**Why.** The desktop agent is the "real" scanner. Until its labels are good enough that a non-technical user reading them recognizes their devices, none of the other surfaces can deliver value. The work for this milestone is mostly already underway in the `agent/` package.

**Scope.** Strategy ranking, labeling-quality regressions, evidence-backed reports against the operator's home network. Cross-cutting: confidence thresholds tuned for "show this label" vs "show as unknown."

**Success signal.** A scan of the operator's home network produces human-readable labels for at least 80% of the devices the operator can identify by sight, with recognized confidence levels for the rest.

**Lane.** [`laptop-wifi-scanner`](epics/laptop-wifi-scanner.md).

**Status (2026-05-14).** Server-side advice baseline expanded — `server/src/advice/engine.ts` now has 7 of the 9 canonical `device_type` rules: `router`, `camera`, `iot`, `printer`, `tv`, `speaker`, `unknown`. `phone` and `laptop` are intentional non-rules (they're operator-owned devices, not Astra-managed). New `bump(current, to)` helper makes risk-level escalation monotonic. 23 advice unit tests in `server/src/advice/__tests__/` (PR [#3](https://github.com/BrooksWimer/Astra/pull/3)). Go agent labeling research is the active forward-work surface; the strategy catalog in `agent/docs/WIFI_STRATEGY_CATALOG.md` is the canonical reference.

---

## M2 — Mobile app delivers Astra's first impression

**Why.** Mobile is the acquisition surface. It needs to feel inviting and produce useful labels within Apple's local-network entitlement constraints — not "nothing scans on iPhone."

**Scope.** Expo / React Native UX, on-device discovery (mDNS / Bonjour + the limited probing iOS allows), phone-to-agent flow when a user has the desktop agent installed, results presentation that doesn't expose scanner internals.

**Success signal.** A first-time user opens the app, taps scan, and sees a meaningful list of devices with labels — with no setup beyond granting local-network permission. If the user later installs the desktop agent, the mobile app shows richer labels via the hosted backend.

**Lane.** [`mobile-wifi-scanner`](epics/mobile-wifi-scanner.md).

---

## M3 — Hosted backend syncs user data across surfaces

**Why.** Cross-device sync is what makes "I scanned at home, my labels are still here at the office" real. Without it, mobile and desktop are two disconnected products. Required for v1 because the value of mobile is partly in seeing what the desktop agent already learned.

**Scope.** User accounts (or pre-account anonymous handles, design-decision pending), schema for shared device labels, sync semantics (last-write-wins vs operator-confirmed merges), conflict UX. Backend already scaffolded under `server/`.

**Success signal.** Operator scans on desktop at home, opens the mobile app at a friend's house with a different network, sees their home labels remembered. Adding a label on mobile reaches the desktop on next refresh.

**Lane.** Cross-cutting — touches `mobile-wifi-scanner` (client-side sync) and a future `server/` slice. Not its own epic; falls under whichever lane the work originates from.

**Status (2026-05-14).** Server-side spine **shipped**. Identity model decision: anonymous handles (UUIDv4 generated once per install). Endpoints in place:

- `POST /scans` — ingest a scan with `{network, devices, scan_started_at}` keyed by the install handle (PR [#6](https://github.com/BrooksWimer/Astra/pull/6))
- `GET /scans/:id` + `GET /scans/latest?handle=<uuid>` — retrieve; cross-handle access returns 404 (no existence leak)
- `POST /scans/:id/advice` — per-device advice + a new **network-level insight aggregator** (`cameras-present`, `iot-density`, `smb-rdp-exposure`, `unknown-coverage`, `new-devices`)
- `PUT /labels` / `GET /labels` / `GET /labels/:deviceId` / `DELETE /labels/:deviceId` — operator-set nicknames + notes, syncable across mobile + desktop via shared handle (PR [#7](https://github.com/BrooksWimer/Astra/pull/7))

Server has its first SQLite (`better-sqlite3`, WAL + FK on) in `src/db/schema.sql`. CI gates merges via `pnpm test` (83 tests) + `pnpm -r run build` + `npx tsc --noEmit` + `go test ./...`.

**Remaining for M3:** mobile + Go-agent integration — each client needs to generate a UUIDv4 at install time and POST scans + read labels. UX decisions (where the handle is displayed for desktop pairing, etc.) are operator calls.

---

## M4 — Router admin ingestion ships at least one real vendor

**Why.** Router-admin ingestion gives users data their LAN scanner alone can't see (DHCP table, signal strength per device, parental controls metadata, etc.). Vendor-agnostic by design — Xfinity at `10.0.0.1` is the first test target because it's the operator's gateway, not because Astra is an Xfinity-only tool.

**Scope.** Credential entry UX, secure credential handling, authentication flow for at least one vendor, navigation/extraction adapter pattern that generalizes (don't hardcode Xfinity selectors), durable notes for vendor-specific discoveries.

**Success signal.** Operator can authenticate Astra against a router admin UI, get a richer device inventory than LAN scanning alone produces, and the implementation pattern is concrete enough that adding a second vendor is days, not weeks.

**Lane.** [`router-admin-ingestion`](epics/router-admin-ingestion.md).

---

## M5 — iPhone hybrid scanning expands the mobile-only experience

**Why.** Apple's local-network entitlement allows Bonjour / mDNS discovery and limited probing, but full active scanning needs the desktop agent. Long-term: a hybrid approach (Bonjour-first, plus what limited probing iOS does allow) gets richer labels without requiring desktop install. This is what makes the mobile-only product genuinely useful.

**Scope.** iOS-side discovery experiments, hybrid label fusion (whatever the phone can see + whatever the backend learned + whatever the desktop agent contributes), feasibility-driven boundary documentation.

**Success signal.** A first-time mobile-only user gets noticeably better labels than mDNS alone could explain. The boundary between what's possible on iPhone and what requires desktop is documented and surfaced in the UX.

**Lane.** [`mobile-wifi-scanner`](epics/mobile-wifi-scanner.md).

---

## Priority order

1. **M1 desktop scanner labeling quality** — required floor. The whole product depends on labels being good.
2. **M2 mobile first-impression** — required for v1 acquisition path.
3. **M3 hosted-backend sync** — required for v1 cross-surface story.
4. **M4 router-admin ingestion (one vendor)** — required for v1 differentiation; without this, Astra is "another LAN scanner."
5. **M5 iPhone hybrid scanning** — post-v1. Makes the mobile-only experience credible without desktop, but not blocking v1.

App Store submission is **not on this roadmap**. It happens when the operator decides to commercialize, after v1 is real.

## Out of scope (durable)

- Network admin / IT-pro features (subnet diagrams, SNMP, advanced topology).
- Security scanning / vulnerability detection.
- Scanner research as an end in itself (research is durable context, not a shipped feature).
- Generic "internet speed test" or "Wi-Fi optimizer" features that aren't device-discovery-grounded.

## See also

- [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) — what Astra is, audience, system shape, planning rules.
- [`PROJECT_MEMORY.md`](PROJECT_MEMORY.md) — durable decisions and conventions.
- [`agent/docs/WIFI_SCANNER_MAP.md`](../../agent/docs/WIFI_SCANNER_MAP.md), [`WIFI_STRATEGY_CATALOG.md`](../../agent/docs/WIFI_STRATEGY_CATALOG.md), [`WIFI_DECISION_RUBRIC.md`](../../agent/docs/WIFI_DECISION_RUBRIC.md), [`LABELING_IMPROVEMENTS_2026-03.md`](../../agent/docs/LABELING_IMPROVEMENTS_2026-03.md) — accumulated scanner research.
