# Netwise Labeling Engine — Project State Handoff

**Last updated:** 2026-03-28
**Prepared for:** AI agent handoff (OpenClaw → Codex/Claude workflow)
**Project:** Netwise LAN scanner — device labeling quality improvement

---

## 1. What This Project Is

Netwise is a Go-based LAN scanner agent that discovers devices on a local network and classifies them into device types. The labeling system is a **hybrid engine** combining:

- **Rules engine** — fast heuristics (gateway IP, hostname patterns, etc.)
- **Fusion engine** — weighted evidence accumulation across all observation strategies

The primary source file is:
```
agent/internal/labeling/labeling.go   (~1573 lines)
```

A Python simulator mirrors the Go logic for rapid iteration without compilation:
```
simulate_labeling.py   (in project root, next to agent/)
```

Run the simulator against any experiment JSON file:
```bash
python3 simulate_labeling.py agent/experiment-foo.json [agent/experiment-bar.json ...]
```

Run a live scan (from `agent/` directory on Windows):
```powershell
go build ./...
go run ./cmd/agent experiment --profile medium --out experiment-live-medium-2.json
```

Profiles: `fast` (~5 min), `medium` (~11 min), `full` (~28–38 min), `label_core` (~2 min, quick probes only)

---

## 2. Label Taxonomy

Valid labels (defined in the engine): `router`, `laptop`, `tv`, `camera`, `printer`, `iot`, `unknown`

Confidence threshold for a label to "stick": **≥ 0.50**

Score-to-confidence formula:
```
base = min(1.0, raw_score / 2.8)
bonus = 0.15 × strong_tier_count + 0.05 × medium_tier_count
confidence = min(1.0, base + bonus)
```

---

## 3. Known Devices on Brooks's LAN (192.168.4.x / 192.168.5.x)

| IP | Device | Expected Label |
|----|--------|---------------|
| 192.168.4.1 | eero router | `router` |
| 192.168.4.20 | Swann IP camera | `camera` |
| 192.168.4.21 | MacBook Pro (AirPlay receiver on port 7000) | `laptop` |
| 192.168.4.23 | AW118 Linux box (SSH, OpenSSH) | `laptop` |
| 192.168.4.196 | Chromecast (port 8009) | `tv` |
| 192.168.4.239 | PS5 (hostname PS5-902BA7.local, Spotify Connect) | `iot` |
| 192.168.5.9 | Sonos Beam soundbar (AirPlay 2, port 1400) | `iot` |
| 192.168.4.253 | Brooks's Windows PC (hostname Brooks.local) | `laptop` (low conf) |

---

## 4. Bugs Fixed in This Session (all changes in `labeling.go` + `simulate_labeling.py`)

### 4.1 SSDP Cross-Device Contamination

**Root cause:** `ssdp_active` broadcasts a multicast M-SEARCH and stores ALL responses from ALL LAN devices against every scanned target IP. `upnp_description_fetch` had the same problem.

**Fix:** Extended `observationEligibleForLabeling()` with cross-device filtering:
- For `ssdp_active` and `upnp_description_fetch`: check `details["entry_ip"]` AND parse source IP from `details["location"]` URL (via new `extractLocationHost()` helper).
- For `ssdp_passive`: added location URL check in addition to existing `entry_ip` check.

**Result:** Router was incorrectly getting `router=0.964` confidence from its own SSDP responses bleeding into every device scan. Now router-specific signals stay on the router.

### 4.2 `ssdp_service_family` Synthetic Key Contamination

**Root cause:** `ssdp_service_family` is a derived key (values: `"router"`, `"device"`, `"media"`, `"audio_video"`) synthesized by the scanner from `ssdp_st` service types. It has no `entry_ip` attribution, so IP-based filtering can't catch it.

**Fix:** Added `ssdp_service_family` (plus `ssdp_observation_mode`, `ssdp_status`, `ssdp_target_match`) to the skip list in the SSDP fusion case.

### 4.3 MacBook Pro Misclassified as `tv`

**Root cause:** Port 7000 is used by both Apple TV and macOS AirPlay receiver. Both `media_device_probe` and `media_device_quick_probe` ran simultaneously and each independently scored port 7000 (0.85 each) + AirTunes banner (0.70 each) + port 1900 (0.25) = `tv=3.35` vs `laptop=2.10`.

**Fix (three parts):**
1. `isQuickProbe` differentiation: when both probes are present, quick_probe uses reduced scores (port 7000: 0.15, AirTunes: 0.15) so the full probe is authoritative.
2. MacBook NetBIOS score raised: `macbook` in netbios name → `laptop` score increased from 1.8 → **2.5**.
3. Removed port 1900/5000 → `tv` attribution from quick_probe `udp_candidate_port`.

**Result:** Full sweeps: `laptop=1.0`, `tv=0.654–0.861`. Laptop wins decisively.

### 4.4 Label-Core Regression (Quick-Probe-Only Scans)

**Root cause:** After fix 4.3 reduced quick_probe scores to prevent stacking, label-core scans (which run *only* `media_device_quick_probe`) showed `tv=0.207` — too low to label.

**Fix:** Made `isQuickProbe` context-aware with a pre-scan:
```go
hasFullMediaProbe := false
for _, s := range profile.Signals {
    if strings.ToLower(s.Strategy) == "media_device_probe" {
        hasFullMediaProbe = true; break
    }
}
isQuickProbe := lowerS == "media_device_quick_probe" && hasFullMediaProbe
```

When only the quick probe is present, it acts as the authoritative probe and uses full scores.

**Result:** Label-core scans: `tv=0.793` for ambiguous AirPlay device (correct — can't distinguish Apple TV from MacBook without NetBIOS in quick mode).

### 4.5 Sonos Beam Misclassified as `tv`

**Root cause (discovered from live scan):** Sonos Beam at `192.168.5.9` supports AirPlay 2 (port 7000, AirTunes/366.0) and advertises `MediaRenderer` + `RenderingControl` UPnP services. The engine accumulated `tv=6.95` raw score from SSDP matches.

**Fix (three parts):**
1. Removed `renderingcontrol` and `basicdevice` from SSDP tv check — these are generic UPnP service types shared by all AV devices. Reduced `mediarenderer` score from 0.85 → 0.55.
2. Added Sonos-specific SSDP signals → `iot`:
   - `ssdp_server` containing `"sonos"` → `iot=2.0`
   - `ssdp_st` / `ssdp_usn` containing `"zoneplayer"` or `"schemas-sonos-com"` → `iot=1.5` each
3. Added `upnp_manufacturer` / `upnp_model_name` containing `"sonos"` → `iot=2.0`
4. Added `sonos_status=real_data` (dedicated probe field) → `iot=3.0`

**Also fixed:** Python simulator winner-selection tiebreaker — when two labels both hit confidence=1.0, raw score now determines the winner (Go already had this).

**Result:** Sonos Beam: `iot=1.0` (raw=17.1 vs tv raw=2.95).

---

## 5. Current Experiment Results (all passing)

### experiment-live-medium-2.json (fresh live scan, 2026-03-28 1am, 11 min)
| IP | Label | Confidence |
|----|-------|-----------|
| 192.168.4.1 (eero) | router | 1.000 ✓ |
| 192.168.4.20 (Swann) | camera | 1.000 ✓ |
| 192.168.4.196 (Chromecast) | tv | 1.000 ✓ |
| 192.168.5.9 (Sonos Beam) | iot | 1.000 ✓ (was tv) |
| 192.168.4.189/233/27/254 | unknown | 0.036 ✓ (TTL only, correct) |

### experiment-deepened-full-sweep-scoped-v3.json (full sweep, all strategies)
| IP | Label | Confidence |
|----|-------|-----------|
| 192.168.4.1 (eero) | router | 1.000 ✓ |
| 192.168.4.20 (Swann) | camera | 1.000 ✓ |
| 192.168.4.21 (MacBook) | laptop | 1.000 ✓ (was tv) |
| 192.168.4.23 (AW118) | laptop | 1.000 ✓ (was unknown) |
| 192.168.4.196 (Chromecast) | tv | 1.000 ✓ |

### experiment-passive-full-sweep.json
| IP | Label | Notes |
|----|-------|-------|
| 192.168.4.21 (MacBook) | laptop=1.0, tv=0.861 | laptop wins ✓ |
| 192.168.4.23 (AW118) | laptop=0.321 | below threshold — no SSH banner captured in this scan |

### experiment-live-medium.json (prior medium sweep, daytime)
| IP | Label | Confidence |
|----|-------|-----------|
| 192.168.4.21 (MacBook) | laptop | 1.000 ✓ |
| 192.168.4.23 (AW118) | laptop | 1.000 ✓ |
| 192.168.4.239 (PS5) | iot | 1.000 ✓ |

### experiment-live-label-core-20260323-context.json (label-core, quick probes only)
| IP | Label | Notes |
|----|-------|-------|
| 192.168.4.21 (ambiguous AirPlay) | tv=0.793 | correct — can't distinguish Apple TV from MacBook without NetBIOS |
| 192.168.4.196 (Chromecast) | tv=1.000 ✓ | |
| 192.168.4.20 (Swann) | camera=1.000 ✓ | |

---

## 6. Key Code Locations

### `labeling.go` — Critical Sections

| Line | What it does |
|------|-------------|
| ~95 | `observationEligibleForLabeling()` — pre-filter observations before fusion scoring; cross-device contamination fixes live here |
| ~135 | `extractLocationHost()` — helper to parse IP from UPnP/SSDP `location` URL |
| ~504 | `fusionEngineWeighted.Score()` — main fusion loop |
| ~524 | `hasFullMediaProbe` pre-scan — detects if full media probe is present |
| ~536 | mDNS scoring |
| ~610 | SSDP scoring (cross-device skip, Sonos signals, MediaRenderer) |
| ~646 | UPnP scoring (brand recognition including Sonos) |
| ~703 | `media_device_probe` / `media_device_quick_probe` case (isQuickProbe logic, Sonos status) |
| ~163 | Candidate sort — confidence primary, raw score tiebreaker |

### `simulate_labeling.py` — Mirrors `labeling.go`

The Python simulator is the fast iteration environment. All logic changes must be applied to **both** files in sync.

Key sections match the Go code:
- `observation_eligible_for_labeling()` — cross-device filter
- `fusion_score()` — main scoring loop; `has_full_media_probe` pre-scan at top
- SSDP block (~line 410), UPnP block (~line 441), media probe block (~line 476)
- `analyze_device()` — winner selection with raw score tiebreaker

---

## 7. Open Items / Potential Next Work

### 7.1 AW118 Low Confidence in Passive-Only Scans (0.321)
`.23` only reaches `laptop=0.321` when the SSH banner isn't captured (passive-only scans). Port 22 is open but without the banner it's below the 0.5 threshold. Options:
- Increase weight of port 22 alone as a laptop signal
- Add `service_family:ssh_admin` → stronger laptop score

### 7.2 MacBook Ambiguity in Label-Core Without NetBIOS
`.21` shows `tv=0.793` in label-core scans (expected, since port 7000 + AirTunes is genuinely ambiguous without hostname). This is acceptable but imperfect. Could potentially improve by:
- Using mDNS service names (Apple advertises `_companion-link._tcp` and `_sleep-proxy._udp` which are mac-specific)
- Using MAC OUI (Apple Silicon MACs have specific OUI prefixes)

### 7.3 No "gaming_console" Label Category
PS5 correctly labels as `iot` (best available), but a dedicated `gaming` label would be more accurate. Requires label taxonomy expansion across the whole system (not just labeling.go).

### 7.4 Devices with Only TTL Signals
Several devices (.189, .233, .27, .254) consistently show `unknown=0.036` — they exist on the network but respond to nothing. These may be IoT devices with aggressive firewalls, or mobile devices that only connect briefly. No actionable fix without more data.

### 7.5 Need Daytime Scan to Validate All Devices Together
The fresh scan (2026-03-28) ran at 1am — MacBook and AW118 were offline. A daytime medium sweep would validate all fixes together in production with all devices active.

---

## 8. Workflow for Future Changes

1. Identify issue in experiment JSON or live scan
2. Inspect device observations in Python:
   ```python
   python3 -c "
   import json
   data = json.load(open('agent/experiment-foo.json'))
   for d in data['devices']:
       if d['ip'] == '192.168.4.XX':
           for obs in d['observations']:
               print(obs['strategy'], obs.get('key',''), obs.get('value',''))
   "
   ```
3. Debug scores:
   ```python
   python3 -c "
   import json, sys; sys.path.insert(0, '.')
   import simulate_labeling as sl
   data = json.load(open('agent/experiment-foo.json'))
   for d in data['devices']:
       if d['ip'] == '192.168.4.XX':
           r = sl.fusion_score(d['observations'], d['ip'])
           for lbl, info in sorted(r.items(), key=lambda x: -x[1]['score']):
               print(lbl, info['score'], info['evidence'])
   "
   ```
4. Edit `simulate_labeling.py` and verify with `python3 simulate_labeling.py agent/experiment-*.json`
5. Mirror changes to `labeling.go` (keep in sync — same logic, different syntax)
6. Build to verify: `cd agent && go build ./...`
7. Run a live scan if needed: `go run ./cmd/agent experiment --profile medium --out experiment-new.json`
