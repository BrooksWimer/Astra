# Netwise

Netwise is a local network scanner project with three active threads:

- a Go LAN scanning agent
- a React Native mobile client
- scanner strategy research focused on better discovery, labeling quality, runtime, and eventual iPhone-only feasibility

Today, the main scanner runs in the Go `agent`. The mobile app is the product surface around that scanner. If you are here to understand or improve the Wi-Fi/LAN scanning itself, start with the research docs below.

## Start Here

- `RESEARCH_BRIEF.md`
- `PUBLIC_SCAN_STATUS.md`
- `agent/docs/WIFI_SCANNER_MAP.md`
- `agent/docs/WIFI_STRATEGY_CATALOG.md`
- `agent/docs/WIFI_DECISION_RUBRIC.md`

## Repo Layout

```text
netwise/
  agent/       Go scanner, strategy system, CLI, and reports
  mobile/      Expo / React Native app
  server/      Node / Express advice and assistant APIs
  shared/      Shared schemas and TypeScript types
```

## Current State

- The desktop Go agent is the current scanner of record.
- The mobile app talks to the agent over HTTP.
- The repo also contains research tooling for:
  - running scanner experiments
  - comparing strategy profiles
  - evaluating labeling quality
  - ranking strategies by value and runtime
- One important long-term question is which parts of the scanner can move to a pure iPhone implementation without depending on a computer host.

## Environment

- Package manager: `pnpm`
- Node: `20.x` recommended on Windows
- Go: `1.21+`

Install JS dependencies from repo root:

```powershell
pnpm install
```

## Validation

If you only want to verify that the repo is in a working baseline state, use these commands first.

### Shared

```powershell
pnpm --filter @netwise/shared test
```

### Server

```powershell
pnpm --filter server build
```

### Agent

Use workspace-local Go caches to avoid host-specific cache and telemetry issues:

```powershell
cd agent
$env:GOCACHE="$PWD\\.cache"
$env:GOMODCACHE="$PWD\\.modcache"
$env:GOTELEMETRY="off"
$env:GONOSUMDB="*"
go test ./...
```

These commands are the current public validation path: a short baseline check that tells a fresh contributor or research agent whether the repo installs and the core packages still work.

## Testing Notes

The current tests are useful, but partial.

What they do cover:

- parser and platform utility behavior in the Go agent
- parts of the labeling and scanner internals
- BLE classification logic in `shared`
- TypeScript compile health for the server

What they do not prove:

- end-to-end scanner accuracy on a real network
- label quality against broad ground truth
- performance on large or unusual LANs
- iPhone-only feasibility

So if you are doing scanner research, treat the tests as regression guards, not as proof that a strategy change is correct.

## Running The System

### Agent

Run from `agent/` so local config is found:

```powershell
cd agent
go run ./cmd/agent
```

Main endpoints:

- `GET /health`
- `GET /info`
- `POST /scan/start`
- `GET /scan/:scan_id`
- `GET /devices`
- `GET /devices/:id`
- `GET /events`

### Server

```powershell
pnpm --filter server dev
```

Default port: `3000`

### Mobile

```powershell
pnpm --filter mobile start
```

The mobile app connects to the agent over HTTP. On a physical device, point it at your machine's LAN IP rather than `localhost`.

## Research Guidance

If you are an outside research agent or contributor, the most valuable help is usually in one of these areas:

- improve device discovery coverage without exploding runtime
- improve label quality for routers, TVs, cameras, printers, and common IoT devices
- identify which strategies are high-value versus expensive noise
- propose a realistic path toward an iPhone-native scanner

If that is your goal, read `RESEARCH_BRIEF.md` and `PUBLIC_SCAN_STATUS.md` before changing code.
