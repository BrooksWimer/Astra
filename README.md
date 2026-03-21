# Netwise — Fing + AI advice MVP

Monorepo: **agent** (Go), **mobile** (Expo RN), **server** (Node/Express AI advice), **shared** (schemas + types).

## Repo structure

```
netwise/
  agent/       # Go: LAN scan, REST API, mDNS
  mobile/      # Expo React Native app
  server/      # Node/Express: /advice rule-based engine
  shared/      # schema.json + TS types
```

**JS workspaces:** pnpm. From repo root: `pnpm install`, then run each part as below.

**Node version (Windows):** On Windows, use **Node 20 LTS** for the mobile app. Node 22+ can cause `ENOENT` when Metro tries to create a path containing `node:sea` (the colon is invalid in Windows paths). Use [nvm-windows](https://github.com/coreybutler/nvm-windows) or install Node 20 from [nodejs.org](https://nodejs.org).

---

## 1. Shared contract

- **`shared/schema.json`** — JSON Schema for Device, ScanResult, AdviceRequest, AdviceResponse.
- **`shared/src/types.ts`** — TypeScript types aligned with the schema (used by server + mobile).

Build shared: `pnpm --filter @netwise/shared build`

---

## 2. Agent (Go)

Runs on your computer; scans the LAN and serves results.

**Run from `agent/` directory** (so `config.json` is found):

```bash
cd agent
go run ./cmd/agent
# or: make run
```

- **Endpoints:**  
  `GET /health`, `GET /info`, `POST /scan/start`, `GET /scan/:scan_id`, `GET /devices`, `GET /devices/:id`, `GET /events` (SSE).
- **mDNS:** Advertises `_netwise._tcp` on port **7777** (TXT: version, device name).
- **Config:** `agent/config.json` — `enable_port_scan`, `ports_to_check`, `scan_timeout_seconds`.
- **Platforms:** ARP table + gateway detection for **macOS** (arp -an), **Linux** (/proc/net/arp), **Windows** (arp -a). TCP probe sweep on subnet for extra hosts.

### Testing the agent (no phone required)

Run the agent, then from another terminal (PowerShell or bash) hit the API to confirm scan and data:

```powershell
# From repo root or any terminal (use your PC's IP or 127.0.0.1 if testing locally)

# 1. Health
Invoke-RestMethod -Uri "http://127.0.0.1:7777/health"

# 2. Agent info (interface, subnet, gateway)
Invoke-RestMethod -Uri "http://127.0.0.1:7777/info"

# 3. Start a scan (returns scan_id)
$r = Invoke-RestMethod -Uri "http://127.0.0.1:7777/scan/start" -Method POST
$scanId = $r.scan_id
Write-Host "Scan ID: $scanId"

# 4. Wait a few seconds, then get scan result (devices for this scan)
Start-Sleep -Seconds 5
Invoke-RestMethod -Uri "http://127.0.0.1:7777/scan/$scanId"

# 5. Get latest devices (all known)
Invoke-RestMethod -Uri "http://127.0.0.1:7777/devices"
```

In the agent terminal you should see: `Scan started: scan_...`, then (after ARP/probe) `Scan finished: scan_..., N devices`. If N is 0 on Windows, run `arp -a` in PowerShell first to confirm your ARP cache has entries; the agent reads the same cache.

---

## 3. Server (AI advice)

Rule-based advice engine (no LLM); responses grounded to provided facts.

```bash
pnpm --filter server dev
# Listens on http://localhost:3000
```

- **`POST /advice`** — Body: `AdviceRequest` (scan_id, device_id, device, network, user_context). Returns `AdviceResponse` (summary, risk_level, reasons, actions, uncertainty_notes).
- **Rules (examples):** router → secure router; unknown device → verify; open 445/3389 on home → flag and recommend review.

---

## 4. Mobile (Expo RN)

**Connect:** Enter agent URL (e.g. `http://192.168.1.10:7777`) or use manual IP.  
**Device list:** “Run Scan” starts a scan; list shows devices with risk badges; polling every 2s during scan if SSE isn’t used.  
**Device detail:** Device facts + “Get Advice” calls the advice server and shows summary, risk, reasons, and actions.

**Advice server URL:** In `mobile/src/screens/DeviceDetailScreen.tsx`, `ADVICE_SERVER` is set to `http://localhost:3000`. On a physical device, set this to your machine’s IP (e.g. `http://192.168.1.10:3000`) so the phone can reach the server.

```bash
pnpm --filter mobile start
# Then press i for iOS or a for Android (or scan QR with Expo Go).
```

---

## Quick run

1. **Terminal 1 — Agent:** `cd agent && go run ./cmd/agent`
2. **Terminal 2 — Server:** `pnpm --filter server dev`
3. **Terminal 3 — Mobile:** `pnpm --filter mobile start` → connect to agent (e.g. `http://<your-pc-ip>:7777`), run scan, open a device, tap “Get Advice” (ensure advice server URL in app points to your PC’s IP when using a real device).

---

## UX notes

- All async calls use timeouts/cancel so the app doesn’t get stuck.
- Scan button shows “Scanning…” and progress while a scan is running.
- Device IP/MAC can be copied from the detail screen.
