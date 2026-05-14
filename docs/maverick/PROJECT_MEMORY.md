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

## 2026-05-14 — Server M3 spine shipped + CI in place

Substantial server-side work landed today via 7 squash-merged PRs on `master`. This entry is the durable record alongside the GitHub PR history.

**Build + tests + CI established (PRs [#1](https://github.com/BrooksWimer/Astra/pull/1), [#2](https://github.com/BrooksWimer/Astra/pull/2), [#5](https://github.com/BrooksWimer/Astra/pull/5)):**
- Server TS build was broken on master with `Type 'undefined' is not assignable to type 'string | null'` because `shared/src/types.ts` modeled `Device.hostname` as `string | null` despite `shared/schema.json` declaring it optional. Fix: `hostname?: string | null` in the shared interface — propagates correctly through the Zod-inferred `AdviceRequest`.
- `device_type` Zod enum was missing `speaker` and `camera` (7 of 9 canonical values). Real `/advice` POSTs for discovered speakers / cameras would have 400'd. Now 9-value enum matches `shared/schema.json`.
- First CI for the repo (`.github/workflows/ci.yml`): four jobs — `shared` (build), `server` (build + 17 tests at the time of #1), `mobile` (`tsc --noEmit`), `agent` (`go test ./...` with `libpcap-dev` install for `gopacket`). Triggers on `master`, `codex/**`, `claude/**`, and all PRs. CI uses vitest auto-discovery instead of `tsx --test` glob (Node-version-portable).
- `server/src/app.ts` factory split from `index.ts` so route tests can listen on an ephemeral port without modifying the production entry.

**Advice engine expanded (PR [#3](https://github.com/BrooksWimer/Astra/pull/3)):**
- 5 new device-type rules: `camera` (critical risk + "Lock down camera defaults" + "Segment cameras"), `iot` (medium risk + "Keep IoT devices isolated"), `printer` / `tv` / `speaker` (informational firmware/privacy actions).
- `bump(current, to)` helper makes risk-level escalation monotonic. Previously a later medium-bumping rule could silently undo an earlier high bump depending on rule ordering. Now risk only increases.
- 23 tests across `engine.test.ts` and `schema.test.ts`.

**M3 spine shipped (PRs [#6](https://github.com/BrooksWimer/Astra/pull/6) + [#7](https://github.com/BrooksWimer/Astra/pull/7)):**
- **Identity model decision:** anonymous handles (UUIDv4-per-install) over user accounts. Validated with the canonical 8-4-4-4-12 hex regex + version + variant nibbles so a typo can't share scope with another install. Pass via `X-Astra-Handle` header or `?handle=` query parameter. Closes the "Privacy / account model" open question from the previous list.
- **`scans`, `scan_devices`, `device_labels`** SQLite tables (`better-sqlite3`, WAL + FK on). Schema is the canonical source in `src/db/schema.sql`; `src/db/schema.ts` re-exports as a string constant so runtime doesn't need to find a non-TS file. Tests use `:memory:` for isolation.
- Endpoints: `POST /scans`, `GET /scans/:id`, `GET /scans/latest?handle=<uuid>`, `POST /scans/:id/advice`, `PUT /labels`, `GET /labels`, `GET /labels/:deviceId`, `DELETE /labels/:deviceId`. Cross-handle access returns 404 (never leaks existence to other handles).
- **`POST /scans/:id/advice`** returns per-device advice + a new **network-level insight aggregator** (`src/scans/insight.ts`) that complements the per-device engine. Five insight types: `cameras-present` (critical), `iot-density` (warn), `smb-rdp-exposure` (warn), `unknown-coverage` (info), `new-devices` (info). Each insight cites the device IDs it draws from so the UI can drill from "you have a camera problem" to "this specific camera at 10.0.0.42."
- Suite goes from 0 → 83 server tests across `advice/__tests__/`, `routes/__tests__/`, `scans/__tests__/`, `labels/__tests__/`.

**Developer onboarding (PR [#4](https://github.com/BrooksWimer/Astra/pull/4)):**
- `DEVELOPMENT.md` at repo root. Prereqs (Node 20 specifically on Windows, pnpm 9+, Go 1.21+, libpcap-dev for agent work). Bootstrap. Validation baseline mirroring the 4 CI jobs in dependency order. Branch + PR conventions. "Where to put new code" cheat sheet. "Common gotchas" capturing the bugs fixed in #1 + the CI quirks from #2.

**Build config:** `server/tsconfig.json` switched from `module: commonjs` to `module: nodenext` to match `package.json`'s `type: module` — pre-existing inconsistency where tsc was emitting CJS into an ESM package.

**Remaining for M3:** mobile + Go-agent client wiring to the new endpoints. Each client needs to generate a UUIDv4 at install time, persist it, and POST scans + read labels. UX decisions about where the handle is displayed for desktop pairing are operator calls.

## 2026-05-14 — Astra missing from resume content.json (open decision)

Flagged during the brookswimer.com PR #9 (resume MASTER_INVENTORY.md population). Astra is featured as a flagship project on the portfolio site (`projects/astra/`), but is absent from `resume/content.json` — the canonical source the resume pipeline (`generator.py`, `html_builder.py`, `renderer.py`) reads when producing the resume PDF. Tailored resumes can't include Astra today.

Decision deferred to the operator: either add Astra to `content.json` with bullets you're comfortable shipping on a job application, or intentionally mark it portfolio-only. The MASTER_INVENTORY.md change in #9 added an explicit `Astra (public name; internal: Netwise) — not yet in content.json` section so future tailoring passes surface the gap rather than silently dropping the project. **Resolution path:** update `resume/content.json` with the Astra entry; remove the "not yet in content.json" note from MASTER_INVENTORY. Cross-repo concern — captured here in Astra/Netwise doctrine because the resume copy needs to match the Astra product story.
