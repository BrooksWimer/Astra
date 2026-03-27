# Research Brief

This file is for outside contributors or research agents who want to improve the Netwise scanner quickly without reverse-engineering the whole repo first.

## The Problem

We want better local network scanning.

In practice, that means improving some combination of:

- device discovery coverage
- device labeling quality
- scan runtime
- strategy selection
- eventual iPhone-only feasibility

Today, the main scanner runs in the Go `agent`. The mobile app is a client around that scanner, not yet a pure on-device scanner.

## What Matters Most

Good research should optimize for practical value, not just more observations.

Priority order:

1. Find real devices on the LAN reliably.
2. Label common home-network devices more accurately.
3. Keep runtime reasonable.
4. Make the strategy set easier to reason about.
5. Where possible, identify which techniques could survive an iPhone-only implementation.

## Important Constraints

### Product and scanner constraints

- The scanner should remain useful on normal home networks.
- More evidence is not automatically better if it mostly adds time and noise.
- The `full` path should remain available as the evidence-maximizing reference path.
- Fast profiles should favor high-yield strategies.

### iPhone feasibility constraints

When proposing "future iPhone-only" ideas, prefer approaches that do not depend on:

- ARP table access
- raw packet capture / pcap
- privileged passive sniffing
- host event logs
- shelling out to OS commands

Ideas that depend on SSDP, Bonjour/mDNS, direct HTTP/TCP probing, and other normal app-visible local-network traffic are more relevant to that goal.

### Apple platform reality

Some local-network discovery approaches on iPhone are restricted by Local Network privacy and multicast entitlement rules. A proposal is more useful if it distinguishes:

- works in the current desktop agent
- plausible in a normal iPhone app
- requires special Apple approval

## Read These Files First

- `PUBLIC_SCAN_STATUS.md`
- `agent/docs/WIFI_SCANNER_MAP.md`
- `agent/docs/WIFI_STRATEGY_CATALOG.md`
- `agent/docs/WIFI_DECISION_RUBRIC.md`
- `agent/internal/scanner/scanner.go`
- `agent/internal/strategy/profile.go`
- `agent/internal/strategy/registry.go`
- `agent/internal/labeling/labeling.go`
- `agent/internal/scanner/experiment.go`

## What A Good Suggestion Looks Like

A strong suggestion usually does most of these:

- identifies a specific bottleneck or blind spot
- names the exact strategy or pipeline stage involved
- explains the expected effect on:
  - discovery
  - labeling
  - runtime
  - iPhone portability
- suggests how to validate the claim

Examples:

- "Move strategy X from fast path to second wave because it adds little unique signal relative to its runtime."
- "Use SSDP plus UPnP description fetch as the iPhone-first discovery path for media and gateway devices."
- "Keep strategy Y only for the full profile because it depends on environment-specific data."

## What Is Less Useful

- suggestions that only maximize total observations
- proposals that assume privileged packet capture is acceptable everywhere
- generic "use AI/ML" advice without integration points
- ideas that do not say how they would be tested

## Validation Baseline

Use these commands first:

```powershell
pnpm --filter @netwise/shared test
pnpm --filter server build

cd agent
$env:GOCACHE="$PWD\\.cache"
$env:GOMODCACHE="$PWD\\.modcache"
$env:GOTELEMETRY="off"
$env:GONOSUMDB="*"
go test ./...
```

## Testing Reality

The current tests are partial.

They are good for:

- parser correctness
- helper logic
- some labeling behavior
- scanner-internal regressions

They are not enough by themselves to prove:

- live-network discovery quality
- real-world label quality
- speed improvements on representative LANs

So if you propose a scanner change, include both:

- the code-level regression story
- the live or replayed evaluation story

## Best Areas For Research Right Now

- Better strategy tiering for fast vs medium vs full
- Higher-yield label evidence for TVs, routers, cameras, and printers
- Reducing expensive low-value probes
- Cleaner replay or benchmark fixtures for scanner evaluation
- A realistic iPhone-native subset of the scanner

## Deliverable Format

The easiest research output to use is:

1. brief diagnosis
2. exact files or strategies affected
3. tradeoffs
4. validation plan
5. optional patch or pseudocode
