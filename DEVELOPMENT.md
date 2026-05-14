# Astra Development Guide

Practical setup, test, and contribution notes for the Astra (internal: Netwise) repo. The product story lives in [`docs/maverick/PROJECT_CONTEXT.md`](docs/maverick/PROJECT_CONTEXT.md); this file covers "how do I clone this and get the tests green."

## Repo layout

```text
netwise/
  agent/       Go LAN scanner (real scanner of record)
  mobile/      Expo / React Native client
  server/      Node / Express advice + sync backend
  shared/      TypeScript schemas + types shared by mobile & server
  docs/        Maverick doctrine + scanner research notes
```

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Node.js | **20.x LTS** | On Windows, **stay on 20**. Node 22+ can `ENOENT` when Metro tries to create a path containing `node:sea` (the colon is invalid in Windows paths). Use [nvm-windows](https://github.com/coreybutler/nvm-windows). |
| pnpm | **9.0.0+** | `corepack enable && corepack prepare pnpm@9 --activate` |
| Go | **1.21+** | Only needed if you're touching the `agent/` package. |
| libpcap headers | **dev package** | Linux/macOS only, only for `agent/` work that builds `gopacket/pcap`. CI installs `libpcap-dev` automatically. |

## Bootstrap

From the repo root:

```bash
pnpm install
```

This installs everything for `mobile/`, `server/`, and `shared/` via pnpm workspaces. The Go agent is independent — see the [Agent](#agent-go) section below.

## Validation baseline

CI (`.github/workflows/ci.yml`) runs four jobs. To reproduce a green CI locally, run them in this order — `shared` must build first because both `server` and `mobile` consume it via `workspace:*`.

### Shared

```bash
pnpm --filter @netwise/shared build
```

`shared/dist/` should appear with the compiled `.js` + `.d.ts` files. Nothing else to verify — shared has no runtime, just types.

### Server

```bash
pnpm --filter server build   # tsc against server/src
pnpm --filter server test    # vitest, 23 tests today
```

Tests live colocated under `server/src/**/__tests__/*.test.ts`. The `tsconfig.json` excludes them from the build, so `server/dist/` stays clean.

To run the server end-to-end against a real scanner:

```bash
pnpm --filter server dev     # tsx --watch on port 3000
```

Routes today: `GET /health`, `POST /advice`.

### Mobile

```bash
cd mobile
npx tsc --noEmit             # what CI runs
pnpm start                   # to actually open the app
```

Mobile has no lint or test scripts yet — adding them is a future slice. The Expo dev client is the only way to exercise BLE / local-network code paths (the iOS simulator can't scan).

### Agent (Go)

The agent is a Go project; it doesn't share lockfiles with the JS workspaces.

```bash
cd agent
go test ./...
```

For long-running scanner sessions, prefer workspace-local caches so you don't pollute your global Go cache with test artifacts:

```powershell
cd agent
$env:GOCACHE = "$PWD\.cache"
$env:GOMODCACHE = "$PWD\.modcache"
$env:GOTELEMETRY = "off"
$env:GONOSUMDB = "*"
go test ./...
```

To run the live scanner against your network:

```bash
go run ./cmd/agent
# or via the repo root:
pnpm agent
```

The agent listens on `http://localhost:3000` by default (yes, same port the server uses — run only one at a time during dev).

## Branch & PR conventions

Maverick conventions, lightly adapted for this repo:

- **`master`** — production. Only PR merges land here.
- **`codex/<topic>-epic`** — operator-driven epic branches (`codex/laptop-wifi-scanner-epic`, etc.).
- **`claude/<topic>`** — autonomous-agent slices that target `master`.
- **`maverick/netwise/<epic-id>/<slug>-<short-id>`** — Maverick-orchestrated workstream branches.

CI runs on `master`, `codex/**`, `claude/**`, and all PRs.

PRs are squash-merged so `master` stays linear and each commit has a `(#N)` suffix.

## Where to put new code

- New **advice rule** → `server/src/advice/engine.ts`, add a test in `server/src/advice/__tests__/engine.test.ts`.
- New **server endpoint** → `server/src/routes/<topic>.ts`, register it in `server/src/index.ts`, add tests under `server/src/routes/__tests__/`.
- New **shared schema field** → update `shared/schema.json` (canonical), reflect it in `shared/src/types.ts`, mirror in any consuming Zod schema (e.g. `server/src/advice/schema.ts`). The 9-vs-7 enum drift fixed in #1 is exactly what happens when one of these gets skipped.
- New **scanner strategy** → `agent/internal/strategy/<name>.go` + register in the profile catalog. The research notes in `agent/docs/` should be updated when a new strategy meaningfully shifts the labeling story.
- New **mobile screen** → `mobile/src/screens/`, navigation lives in `mobile/src/navigation/`.

## Where to find context

- [`README.md`](README.md) — product / system overview.
- [`docs/maverick/PROJECT_CONTEXT.md`](docs/maverick/PROJECT_CONTEXT.md) — audience, mobile-vs-desktop split, naming rules.
- [`docs/maverick/PROJECT_ROADMAP.md`](docs/maverick/PROJECT_ROADMAP.md) — M1–M5 milestones with success signals.
- [`docs/maverick/PROJECT_MEMORY.md`](docs/maverick/PROJECT_MEMORY.md) — durable decisions, lab network targets, naming conventions.
- [`docs/maverick/epics/*.md`](docs/maverick/epics/) — per-lane charters (`laptop-wifi-scanner`, `mobile-wifi-scanner`, `router-admin-ingestion`).
- [`agent/docs/`](agent/docs/) — accumulated scanner research (`WIFI_SCANNER_MAP.md`, `WIFI_STRATEGY_CATALOG.md`, `WIFI_DECISION_RUBRIC.md`, `LABELING_IMPROVEMENTS_2026-03.md`).
- [`AGENTS.md`](AGENTS.md) — orchestration doctrine + verification baseline (loaded by Codex / Claude Code at session start).

## Common gotchas

- **`pnpm -r run build` fails with `Type 'undefined' is not assignable to type 'string | null'`** — you're on a branch before #1 was merged or you reintroduced the `Device.hostname` drift. The canonical schema (`shared/schema.json`) does not require `hostname`, so the shared TS type must be `hostname?: string | null`.
- **`/advice` returns 400 for a discovered speaker or camera** — you're on a branch before #1 was merged or the Zod `device_type` enum is out of sync with `shared/schema.json`'s 9-value enum. The canonical values are `phone, laptop, router, printer, tv, speaker, camera, iot, unknown`.
- **Agent tests fail in CI with `pcap.h: No such file or directory`** — your CI step doesn't install `libpcap-dev`. The default workflow does (`apt-get install -y libpcap-dev`); a forked workflow may have dropped it.
- **`vitest` not found when running `pnpm --filter server test`** — re-run `pnpm install` at the repo root; pnpm 9 needs explicit install after the lockfile updates.
