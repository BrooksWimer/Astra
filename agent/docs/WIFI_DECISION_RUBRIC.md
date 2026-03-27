# Wi-Fi Decision Rubric

This rubric is the operator rulebook for deciding what to do with a strategy after you understand what it does.

## Decision Buckets

| Bucket | Meaning | Typical traits |
| --- | --- | --- |
| `fast default` | Belongs in the first pass. | Low or very-low cost, broad utility, helps discovery or gives decisive label lift quickly. |
| `second wave` | Useful, but not worth paying for on every first pass. | Medium or high cost, or strong but situational label lift. |
| `device-triggered deepening` | Run only when a device class or user action justifies it. | Expensive specialist, narrow target family, high payoff when it hits. |
| `research only` | Keep available for experiments and baselines, but do not rely on it for product defaults. | Contextual, noisy, enterprise-only, or hard to validate. |
| `drop` | Remove from a candidate profile. | Adds time, duplicates stronger signals, or does not affect operator decisions. |

## The Four Questions To Ask Per Strategy

1. Does it help find devices, or only label existing devices?
2. How much wall-clock time does it cost on the benchmark network?
3. What real observations does it add that other strategies do not already cover?
4. What decision becomes easier because of it?

If you cannot answer question 4, the strategy is probably not ready for the fast path.

## Default Rules

### Keep in `fast default`

Keep a strategy in fast path when most of these are true:

- `speed_cost` is `very_low` or `low`
- it helps discovery or closes a frequent label gap quickly
- it hits many targets, not just a narrow niche
- removing it causes obvious label or operator-quality loss
- its outputs are understandable enough to debug without guesswork

### Move to `second wave`

Move a strategy to second wave when:

- it is useful but not foundational
- it takes noticeable time or network fan-out
- it mainly enriches already-known devices
- it overlaps with cheaper first-pass signals

### Make it `device-triggered deepening`

Use target-triggered deepening when:

- the strategy is expensive
- it has high payoff for one or two device families
- you can define a clear trigger such as:
  - open port pattern
  - SSDP or mDNS family
  - user-selected device
  - unresolved unknown after fast pass

### Mark as `research only`

Use this when:

- the strategy is contextual rather than directly attributable
- the environment dependency is high
- the signal is interesting but not reliable enough to steer defaults
- replay quality is better than live quality and you do not yet trust it in production decisions

### Drop from the candidate profile

Drop a strategy from a target profile when:

- it adds time with no real-data advantage
- it duplicates a cheaper existing signal
- it mostly produces unsupported / no-data / not-applicable outcomes
- it does not change operator behavior even when it succeeds

## Review Loop

Use the same loop every time.

### 1. Establish the baseline

- Keep one benchmark network.
- Keep one anchor profile while learning.
- Use `label_core` as the first anchor unless you are explicitly reviewing the second wave.

### 2. Measure the live run

```powershell
go run ./cmd/agent experiment --profile label_core --out experiment-current.json
```

Read:

- `scan_duration_ms`
- `strategy_reports[].duration_ms`
- `strategy_reports[].targets_hit`
- `strategy_reports[].real_data_observations`

### 3. Evaluate label quality

```powershell
go run ./cmd/agent evaluate --inputs experiment-current.json --out evaluation-current.json
```

Read:

- labeled vs unknown counts
- confidence bands
- conflicts
- ablation notes when available

### 4. Compare profile value

```powershell
go run ./cmd/agent optimize --inputs experiment-current.json --report experiment-current.json --out optimization-current.json
```

Read:

- `strategy_rankings`
- `value_per_unit_time`
- `label_agreement_loss`
- `unknown_increase`
- `average_confidence_loss`

### 5. Assign the strategy

For each reviewed strategy, write down:

- discovery or labeling
- runtime cost
- targets hit
- real observations added
- overlap with other strategies
- current placement
- proposed placement
- reason for the move

## What Counts As Proof

Do not move a strategy just because it feels good or because it emits interesting data.

Treat a move as justified only when at least one of these is true:

- first useful result is meaningfully faster
- an important known label is preserved
- unknown-device resolution improves
- operator triage becomes easier
- the Wi-Fi/BLE correlation layer gets stronger with evidence you can explain

## Guardrails

- Do not add new strategy families until the current catalog is understood.
- Do not change multiple profile placements at once when learning; isolate one move at a time.
- Do not trust replay alone for fast-path placement; validate live timing.
- Keep `full` intact as the reference path while you learn.
- Use the catalog export to inspect strategy purpose and profile membership before making placement calls.
