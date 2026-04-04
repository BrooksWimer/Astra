# Prompt For A Deep Analysis Agent

You are working inside the Netwise repo at:

`C:\Users\wimer\Desktop\Sentry\netwise`

Your job is to deeply analyze why the fast scan path still underperforms the full scan, and propose the best path to a sub-2-minute scan that preserves the strongest labels.

Read this context brief first:

- `C:\Users\wimer\Desktop\Sentry\netwise\agent\DEEP_FAST_SCAN_CONTEXT.md`

Then inspect these artifacts and code paths:

- `C:\Users\wimer\Desktop\Sentry\netwise\agent\experiment-passive-full-sweep.json`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\evaluation-report-passive-full-sweep.json`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\labeling-dataset-passive-full-sweep.json`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\experiment-deepened-full-sweep-scoped-v3.json`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\optimization-report-scoped-v3-current.json`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\experiment-live-label-core-20260323-context.json`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\experiment-live-label-core-20260323-postfix.json`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\internal\strategy\profile.go`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\internal\strategy\media_device_quick_probe.go`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\internal\strategy\upnp_description_fetch.go`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\internal\labeling\labeling.go`
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\internal\scanner\experiment.go`

Primary goal:

- Preserve the best known 4 labels on this network:
  - camera
  - router
  - tv
  - tv
- Get the practical scan path under 2 minutes wall clock
- Keep the full scanner intact

Constraints:

- Do not remove or weaken the full scanner
- Do not rewrite the project into a new architecture
- Keep changes compatible with the existing codebase
- Favor practical signal quality and attribution quality over raw observation count
- A strategy that emits a lot of data but adds little unique label value should rank low

Important known facts:

- Fresh full sweep from 2026-03-23 produced 4 labels but took ~37m 48s
- Current same-day `label_core` fast path took ~2m 03s to ~2m 06s and preserved only 3 labels
- The missing label is the camera
- Two concrete issues were already identified locally:
  - UPnP fetches were incorrectly honoring proxy env vars for local LAN requests
  - `media_device_quick_probe` was not scoring `port:554` for camera in the quick-path media branch
- Those issues were patched locally, but the camera still remains `unknown`
- After the fixes, the camera still only gets `port:554` as effective evidence in fast mode, even though UPnP metadata is successfully collected

What I want from you:

1. Determine exactly which signals the 4 labeled devices depend on in the full sweep.
2. Rank the strategies by true value per unit time, not by observation count alone.
3. Explain why the camera still fails in the fast path after the proxy and `554` fixes.
4. Identify the cheapest path to preserve the camera label without reintroducing the whole full scan.
5. Decide whether the best answer is:
   - a better `label_core` profile,
   - a new fast/medium tier split,
   - a tiny camera-specific second wave,
   - better derived heuristics from existing UPnP/SSDP/RTSP evidence,
   - or a selective reintroduction of one or two omitted strategies.
6. Call out any bugs, attribution leaks, replay-vs-live mismatches, or misleading experiment assumptions.

Please produce:

- A ranked list of strategy families by value
- A root-cause explanation for the camera miss
- A recommended fast profile for live use
- A recommended second-wave profile if needed
- A short list of code changes you would make first
- A list of experiments you would run next, in order

Be explicit about the difference between:

- historical corpus replay
- live wall-clock behavior
- collection failure
- labeling failure
- attribution failure

If you infer something rather than directly observe it from artifacts, label it as an inference.
