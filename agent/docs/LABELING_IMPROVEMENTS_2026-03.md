# Labeling Improvement Research Notes — March 2026

## Summary

This document records the diagnostic findings and code changes made to improve device labeling quality in the Netwise scanner. The focus was on the `label_core` profile, which scored only 3/18 devices in the baseline scan (`experiment-live-label-core-20260323-postfix.json`).

---

## Root Cause Analysis

### 1. MAC Address Randomization

Modern devices (iOS 14+, Android 10+, Windows 10+) use locally-administered (randomized) MAC addresses. When `mac_is_locally_admin = true`, the vendor lookup returns "Unknown", which is then suppressed in `classify.go` to prevent false vendor-based signals. This means the majority of home network devices have no OUI signal.

**Impact:** 5/18 devices in the baseline scan had locally-administered MACs. Another 12 had MACs with unrecognized OUIs (vendor = "Unknown"). Only the scanner host itself had a real vendor.

### 2. mDNS Cache Not Included in label_core

The scanner seeds an mDNS browse cache at startup (`mdns.Browse` runs for 5 seconds during scanner init). The `mdns_active` strategy reads from this pre-seeded cache — adding it to a profile has near-zero runtime cost. However, `mdns_active` was not in `label_core`, meaning mDNS service names and hostnames were unavailable for labeling.

**Impact:** Zero mDNS observations in the baseline label_core scan. Adding `mdns_active` to label_core would have provided service-level classification for devices advertising mDNS (phones via `_companion-link`, Macs via `_afpovertcp`, printers via `_ipp._tcp`, etc.).

### 3. UPnP Manufacturer/Model Data Ignored for Device Brands

The `upnp_description_fetch` strategy successfully retrieved device manufacturer and model names from UPnP description XML. However, the fusion engine (`labeling.go`) did not check these fields for known device brand names. A SWANN DVR8-1550 security camera had its manufacturer ("SWANN") and model ("SWANN DVR8-1550") in UPnP data but was labeled "unknown" because "SWANN" wasn't in any classification pattern.

**Impact:** Device .20 (SWANN DVR8-1550 camera) was labeled "unknown" instead of "camera" despite clear UPnP brand evidence.

### 4. RTSP Response Not Used as Camera Signal

The `media_device_quick_probe` strategy probes port 554 and attempts RTSP negotiation. For the SWANN DVR, it received a valid RTSP response (`rtsp_status = real_data`, `rtsp_realm = /`). However, the fusion engine only checked port numbers, not RTSP response keys. An active RTSP response is a near-definitive camera/NVR signal.

**Impact:** RTSP real_data response contributed 0 to camera confidence.

### 5. media_device_quick_probe at TierWeak

The `media_device_quick_probe` strategy was not in evidence.go's TierMedium case, falling through to the default case which assigned `TierWeak` for port observations. With score/2.8 = 0.55/2.8 = 0.196 and no support tier bonuses, port 554 detection alone couldn't reach the 0.50 confidence threshold.

**Impact:** Port-based camera detection was insufficient alone for labeling.

### 6. port_service_correlation service_family Key Ignored

The `port_service_correlation` strategy emits a `service_family` key with values like "camera", "printer", "tv". This key was silently ignored in the fusion engine because the port number switch case tried to parse "camera" as a port number.

**Impact:** A `service_family=camera` observation from port correlation added nothing to camera confidence.

### 7. iot Over-Classification in Medium Profile

In the medium profile, 11/14 devices were labeled "iot". Key contributors:
- `packet_ttl_os_fingerprint` → iot:0.10 (every visible device)
- `icmp_reachability` → iot:0.05 (every reachable device)
- `_spotify-connect._tcp` mDNS match → iot:0.65 (high-weight, and potentially affecting wrong devices due to IP mismatch in mDNS cache)

The TTL and ICMP signals are intentionally weak. The Spotify Connect issue appears to be a mDNS cache IP mismatch where a PS5's Spotify entry is matched to other devices.

---

## Changes Made

### `agent/internal/strategy/profile.go`

**1. Promoted `mdns_active` from TierSecondWave to TierFastPath**

Rationale: `mdns_active` reads from a pre-seeded cache populated at scanner init, so its strategy-phase cost is negligible. The mDNS browse already runs unconditionally during initialization. Keeping it in TierSecondWave was costing labeling quality with no speed benefit.

**2. Added `mdns_active` to label_core**

Expands label_core from 7 to 8 strategies. Brings mDNS service and hostname data into the label pass, enabling detection of phones (via `_companion-link`), Macs (via `_afpovertcp`, `_ssh`), printers (via `_ipp._tcp`), and media devices.

**3. Added `netbios_llmnr_passive` to label_core**

NetBIOS/LLMNR passive is TierFastPath and SpeedLow. It provides Windows hostname naming at near-zero cost. Useful for Windows laptops and desktops that broadcast their names, which can then feed into the hostname-based classification patterns.

---

### `agent/internal/evidence/evidence.go`

**Added `media_device_quick_probe` to TierMedium case**

Previously `media_device_quick_probe` fell through to the default case and received `TierWeak` for port observations. Since it actively probes specific ports (not just passive port scanning), its observations should carry the same weight as `media_device_probe`. The change enables port-based signals from quick probes to receive the TierMedium support tier bonus in `scoreToConfidence`.

---

### `agent/internal/labeling/labeling.go` (fusion engine)

**1. mDNS: Apple mobile device services → phone**

Added detection of `_companion-link`, `_apple-mobdev`, `_apple-mobdev2`, `_apple-pairable` (score: 1.05). These services are unique to iPhones and iPads.

**2. mDNS: macOS file/remote-access services → laptop**

Added `_afpovertcp`, `_rfb.`, `_sftp-ssh`, `_smb.`, `_device-info._tcp` (score: 0.65). These are macOS-specific network services rarely advertised by non-Mac devices.

**3. mDNS: Smart speaker services → iot**

Added `_amzn-wplay`, `_amazon`, `_googlezone`, `google-cast-group` (score: 0.75). Amazon Echo and Google Home group services.

**4. mDNS: `_ssh._tcp` service → laptop**

SSH via mDNS is almost always a laptop or NAS (score: 0.55).

**5. mDNS instance/hostname name matching**

When `mdns_instance` or `mdns_hostname` contains device-type indicators:
- `iphone`, `ipad` → phone (0.85)
- `macbook`, `mac mini`, `imac`, `mac pro` → laptop (0.85)
- `galaxy`, `pixel`, `android` → phone (0.70)
- `synology`, `qnap`, `diskstation`, `nas` → iot (0.75)
- `apple tv`, `appletv` → tv (0.90)
- `raspberry pi` → iot (0.80)
- `ps5-`, `ps4-`, `playstation`, `xbox-`, `steamdeck` → iot (0.85)
- `echo-`, `alexa-`, `amazon-echo` → iot (0.85)
- `chromecast`, `roku-`, `fire-tv`, `androidtv` → tv (0.85)
- `desktop-`, `laptop-`, `win-`, `windows-` → laptop (0.65)

**6. UPnP: Camera brand detection**

New check for manufacturer/model/friendly_name fields:
- Camera brands (SWANN, Hikvision, Dahua, Reolink, etc.) → camera (0.95)
- Printer brands (Epson, Canon, HP, Brother, etc.) → printer (0.85)
- Router brands (Netgear, TP-Link, eero, Ubiquiti, etc.) → router (0.80)
- TV brands (Samsung, LG, Sony, Vizio, etc.) → tv (0.75)

**7. UPnP: DVR/NVR device type keywords → camera**

Added `dvr`, `cctv`, `surveillance`, `embeddednetdevice` as camera signals (0.85).

**8. RTSP response keys as camera signals**

- `rtsp_status = real_data` → camera (1.2) — active RTSP server means camera
- `rtsp_realm` set → camera (0.6) — RTSP auth realm indicates live server
- `rtsp_server` set → camera (0.7) — server banner confirms camera

**9. port_service_correlation service_family handling**

When `key = service_family`, now dispatches directly to the correct device type rather than trying to parse the value as a port number. Values: `camera → 0.75`, `printer → 0.65`, `tv → 0.65`, `router → 0.60`.

**10. SSDP: ssdp_server brand detection**

When `key = ssdp_server`, checks for:
- Camera brands (Hikvision, SWANN, etc.) → camera (0.75)
- Router brands (eero, Netgear, etc.) → router (0.65)
- TV brands (Samsung, LG, Sony, etc.) → tv (0.60)

**11. Vendor OUI patterns**

Added to the identity family vendor handling:
- Intel Corporate (laptop networking OUI) → laptop (0.30)
- Amazon Technologies / Lab126 → iot (0.55)
- Espressif (ESP32/ESP8266 IoT chips) → iot (0.65)
- Raspberry Pi Trading → iot (0.70)
- Amlogic, Rockchip, Allwinner (smart TV SoCs) → tv (0.40)

**12. Hostname patterns**

Added hostname-based hints:
- `iphone`, `ipad` → phone (0.55)
- `macbook`, `mac-mini`, `mac-pro` → laptop (0.55)
- `galaxy`, `pixel`, `oneplus`, `android` → phone (0.45)
- `synology`, `qnap`, `diskstation`, `readynas`, `nas` → iot (0.55)

**13. NetBIOS/LLMNR hostname name matching**

New case for `netbios_llmnr_passive` strategy. Previously the fusion engine had no handler for this strategy, so `netbios_name = MACBOOK-PRO-167` was collected but scored zero.

- `macbook`, `mac-mini`, `mac-pro`, `imac` → laptop (0.85)
- `iphone`, `ipad` → phone (0.75)
- `galaxy`, `pixel`, `android`, `oneplus` → phone (0.65)
- `desktop-`, `laptop-`, `win-`, `workstation` → laptop (0.65)
- `synology`, `qnap`, `nas`, `diskstation`, `readynas` → iot (0.65)
- `ps5-`, `ps4-`, `playstation`, `xbox-` → iot (0.75)
- `netbios_role = workstation` → laptop (0.30)
- `netbios_role = server/domain_controller` → laptop (0.40)

**14. LLMNR query name → Windows device hint**

New case for `llmnr_responder_analysis` strategy. LLMNR is a Windows-primary protocol; any device sending LLMNR queries is almost certainly a Windows device. Adds laptop (0.35) baseline for any `llmnr_query_name`, plus name-pattern matching.

**15. `firewall_traffic_profile` SSH banner handling**

New case for `firewall_traffic_profile`. This strategy reads from local firewall/router connection logs and was emitting `firewall_ssh_banner` and `firewall_ssh_status=real_data` observations that were completely unhandled. Device .23 (AW118, OpenSSH 9.9) had confirmed SSH via firewall logs but was labeled "unknown" at confidence 0.25.

- `firewall_ssh_status = real_data` → laptop (0.85)
- `firewall_ssh_banner` (non-empty) → laptop (0.60)
- banner contains `openssh` → laptop (0.40 additional)
- banner contains `dropbear` → iot (0.45)
- banner contains `cisco/ios/nexus/junos` → router (0.65)

**16. `service_family = ssh_admin` handling**

`port_service_correlation` emits `service_family=ssh_admin` when port 22 is open. Previously only `camera`, `printer`, `tv/media`, `router` families were handled — SSH was silently dropped.

- `service_family = ssh_admin` or `ssh` → laptop (0.55)

---

### `agent/internal/classify/classify.go` (rules engine)

**1. Apple device disambiguation**

- `macbook`, `mac-mini`, `imac`, `mac-pro` → laptop (0.60), overrides the Apple → phone rule
- `apple-tv`, `appletv` → tv (0.70), overrides the Apple → phone rule

**2. New vendor patterns**

- Espressif → iot (0.65)
- Amazon Technologies, Lab126, echo, alexa, kindle, fire-tv → iot (0.65)
- Intel Corporate → laptop (0.45)
- Synology, QNAP, DiskStation, ReadyNAS → iot (0.65)
- Galaxy, Pixel, OnePlus, Xiaomi, Redmi, android → phone (0.50)

**3. Expanded `classifyFromString`** (used for SSDP server string)

Added camera brand names (Dahua, SWANN, Reolink, Amcrest, DVR, CCTV), printer keywords (LaserJet, OfficeJet, Pixma, Epson), additional TV brands, and router brands to the SSDP server string classification function.

---

## Expected Impact

### label_core profile

Before: 3/18 devices labeled (router, 2x tv)

After (expected for next live scan):
- Camera (.20 SWANN DVR): RTSP real_data + UPnP SWANN brand → camera ~0.97
- Router (.1): unchanged → router 1.00
- TV (.21, .196): unchanged → tv
- Devices with mDNS data: improved via mdns_active in label_core
- Windows PCs: improved via netbios_llmnr_passive in label_core

### full/medium profiles (benchmark: experiment-deepened-full-sweep-scoped-v3.json)

Previous labeled: router (1.00), 2x tv, camera — total 4/10 with evidence

Expected improvements after second-session changes:
- Device .23 (AW118): `firewall_ssh_status=real_data` + `service_family=ssh_admin` + `llmnr_query_name=AW118` → laptop confidence ~1.0 (was 0.25 "unknown")
- Device .20 (SWANN DVR): `camera_probe` results now scored via new camera_probe case → camera confidence +significant boost on top of existing RTSP/UPnP signals
- Devices .27, .189, .239, .250, .251: Still unknown — randomized MACs, no mDNS services, no NetBIOS names, no open ports, passive capture unavailable. Genuinely unidentifiable without passive traffic data.

### Hard floor: 5 unknown devices

Analysis of the 5 remaining unknowns in the benchmark scan confirms they cannot be labeled with current active-only probing:
- All have locally-administered (randomized) MACs
- No mDNS service advertisements
- No NetBIOS names (nbtstat returns no records)
- No open TCP ports detected
- No LLMNR responses
- `packet_ttl_os_fingerprint` returns TTL=64 for some (Linux/Android/iOS/macOS range) — too broad to classify

These are almost certainly smartphones with strict privacy settings (iOS 14+ random MAC, no visible services). Resolving them requires either passive traffic capture (fixing pcap permissions) or a longer passive collection window to catch DNS/TLS/mDNS traffic.

---

## Validation Plan

Run the test suite first:
```powershell
cd agent
$env:GOCACHE="$PWD\.cache"
$env:GOMODCACHE="$PWD\.modcache"
$env:GOTELEMETRY="off"
$env:GONOSUMDB="*"
go test ./...
```

Then run a fresh label_core experiment and compare against the baseline:
```powershell
go run ./cmd/agent experiment --profile label_core --out experiment-after-improvements.json
go run ./cmd/agent evaluate --inputs experiment-after-improvements.json --out evaluation-after.json
```

Key metrics to check (label_core):
- Labeled devices: expect 4+ (up from 3), with .20 now labeled as camera
- Confidence of SWANN device: expect > 0.90
- Scan duration: should stay under 150s (mdns_active adds ~0s, netbios_llmnr_passive adds ~2-5s)

Also run a full scan to validate the firewall_traffic_profile + LLMNR fixes:
```powershell
go run ./cmd/agent experiment --profile full --out experiment-after-full.json
go run ./cmd/agent evaluate --inputs experiment-after-full.json --out evaluation-after-full.json
```

Key metrics to check (full):
- Device .23 (AW118): expect laptop > 0.90 (was unknown 0.25)
- Device .20 (SWANN): expect camera > 0.97
- Total labeled: expect 5+ out of 10 (up from 4)

---

## Files Modified

| File | Change Type |
|------|-------------|
| `agent/internal/strategy/profile.go` | mdns_active tier + label_core profile expansion |
| `agent/internal/labeling/labeling.go` | Fusion engine: mDNS, UPnP brand, RTSP, service_family, SSDP server, camera_probe, SSH, NetBIOS/LLMNR, firewall_traffic_profile |
| `agent/internal/evidence/evidence.go` | media_device_quick_probe tier elevation |
| `agent/internal/classify/classify.go` | Rules engine: Apple disambiguation, new vendor/brand patterns |
