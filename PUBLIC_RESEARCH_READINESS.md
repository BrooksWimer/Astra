# Public Repo And Research Readiness

This repo already has useful scanner architecture docs, but it is not ready to publish as-is if the goal is safe public sharing and efficient outside research help.

## Current State Summary

- The working tree is dirty and includes a large amount of in-progress work.
- The scanner side is well documented in:
  - `agent/docs/WIFI_SCANNER_MAP.md`
  - `agent/docs/WIFI_STRATEGY_CATALOG.md`
  - `agent/docs/WIFI_DECISION_RUBRIC.md`
- The JS side is reasonably reproducible:
  - `pnpm --filter @netwise/shared test` passes
  - `pnpm --filter server build` passes
- The Go agent is also testable, but the easiest stable command in this environment needs local cache env vars:

```powershell
$env:GOCACHE="$PWD\\.cache"
$env:GOMODCACHE="$PWD\\.modcache"
$env:GOTELEMETRY="off"
$env:GONOSUMDB="*"
go test ./...
```

## Must Fix Before Making The Repo Public

### 1. Remove or sanitize live network artifacts

The repo currently contains many checked-in live experiment and evaluation files with real local network data.

Examples:

- `agent/experiment-live-label-core-20260323-context.json`
- `agent/experiment-live-full.json`
- `agent/evaluation-report-passive-full-sweep.json`
- `agent/labeling-dataset-deepened-full-sweep.json`

These include:

- private LAN IP ranges
- device MAC addresses
- local interface names and MACs
- gateway information
- device hostnames and product names
- local scan timing and environment details

At audit time, there were:

- 41 tracked agent artifact files matching `experiment*`, `evaluation-report*`, `labeling-dataset*`, `optimization-report*`, or `tmp-*`
- 48 additional untracked files in the same family

Recommended action:

- Move raw live artifacts out of the repo, or
- Replace them with sanitized fixture data under a dedicated folder such as `agent/testdata/`, and
- Document what was anonymized so outside researchers do not mistake the sanitized values for real topology.

### 2. Remove local-agent prompt files and absolute local paths

These files are useful for one local workflow, but they are not good public-facing repo documents:

- `agent/DEEP_FAST_SCAN_CONTEXT.md`
- `agent/DEEP_FAST_SCAN_PROMPT.md`

They contain:

- absolute local Windows paths
- local-only proxy/debug instructions
- references to private artifacts and one-off experiment files

Recommended action:

- Remove them from the public repo, or
- Rewrite them into a generic `RESEARCH_BRIEF.md` with relative paths and sanitized examples.

### 3. Do not publish from the current dirty branch state

The current branch has many modified source files and many untracked additions across:

- `agent`
- `mobile`
- `server`
- `shared`

Recommended action:

- Create a clean public-prep branch from the intended source baseline
- Add only the files you explicitly want public
- Review `git status --short` until the branch contains a deliberate, minimal diff

### 4. Add a license

There is currently no top-level `LICENSE` file.

Without a license, the repo may be visible but is not clearly open for reuse or contribution.

Recommended action:

- Add a top-level `LICENSE`
- Prefer a standard license rather than custom wording

## Strongly Recommended For Outside Research

### 5. Create one public research brief

The agent docs explain the scanner internals well, but an outside research agent still needs one short document that answers:

- What exact problem should be improved?
- What constraints matter most: speed, coverage, labeling precision, iPhone viability, App Store constraints?
- Which current results are considered good or bad?
- Which strategies are in scope to change?
- What kinds of suggestions are not useful?

Recommended action:

- Add `RESEARCH_BRIEF.md` at repo root

Suggested contents:

- Product goal
- Current scanner architecture
- Current bottlenecks
- iPhone-only constraints
- Open questions
- "How to propose changes" section

### 6. Keep only a small, curated benchmark corpus

Right now there are many experiment snapshots. That creates noise.

Recommended action:

- Keep 2-4 curated benchmark artifacts only
- Name them by purpose, not by local chronology

Example:

- `agent/testdata/benchmark_label_core_sanitized.json`
- `agent/testdata/benchmark_full_sanitized.json`
- `agent/testdata/benchmark_passive_only_sanitized.json`

Each benchmark should have:

- a short description
- what profile produced it
- what "good" looks like
- known caveats

### 7. Document the exact verification commands

Outside researchers work best when they can validate changes with a short command list.

Recommended action:

- Add a "Validation" section to the root README or research brief

Suggested commands:

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

### 8. Add CI for the public baseline

There is no repo-level CI configuration checked in.

Recommended action:

- Add a simple GitHub Actions workflow that runs:
  - shared tests
  - server build
  - agent tests

This matters because outside research suggestions are much easier to trust when the repo has one green baseline.

### 9. Separate "operator docs" from "public docs"

The current `agent/docs` content is good, but it is still operator-oriented.

Recommended action:

- Keep `agent/docs/*` for deep scanner internals
- Add a short top-level `docs/` or root-level brief for new external readers

## Nice To Have

### 10. Add contribution guidance

Useful public additions:

- `CONTRIBUTING.md`
- `SECURITY.md`
- issue templates or a short "how to reproduce" note

### 11. Reduce artifact clutter in the repo root of `agent/`

The `agent/` directory currently mixes:

- source
- docs
- datasets
- evaluations
- optimization outputs
- scratch ablation results

Recommended action:

- Move kept benchmark data under `agent/testdata/`
- Move generated reports under `agent/reports/`
- Remove scratch `tmp-*` outputs from version control

## Best Next Public Shape

If the goal is "make this easy for a deep research agent to improve Wi-Fi scanning", the best public repo shape is:

- clean source tree
- no live home-network data
- 1 root README
- 1 root `RESEARCH_BRIEF.md`
- 1 license
- 1 CI workflow
- 2-4 sanitized benchmark fixtures
- clear validation commands

That would give an outside agent enough context to:

- understand the scanner quickly
- reproduce a baseline
- reason about tradeoffs
- propose changes against known benchmark inputs

without exposing private LAN data or forcing the agent to reverse-engineer your local workflow.
