# Xfinity Gateway Baseline Discovery

Date: `2026-04-05`
Target: local Xfinity gateway UI at `http://10.0.0.1`

## Why this note exists

This note captures the durable baseline before any router-admin scraper implementation begins.

## Confirmed facts

- The local gateway UI is reachable from the laptop.
- The login entry point is `http://10.0.0.1/index.jst`.
- Login submits to `check.jst`.
- `http://10.0.0.1/connected_devices_computers.jst` is an authenticated page.
- Browser-session-based inspection has worked; direct shell fetches do not inherit the logged-in browser session.
- A public Xfinity account path was explored accidentally at first and should be ignored for this epic.

## Authenticated UI observations

- The connected-devices page is visible after login.
- Visible device names include `Brooks`, `iPhone-83`, `eero`, multiple `AiDot` bulbs, `SonosZP`, `amazon-454178a7c`, and `L-H5CG3025X72`.
- Offline devices shown in the UI include `raspberrypi4` and `XBOXONE`.
- Device entries on the connected-devices page are rendered as `javascript:void(0)`.
- That strongly suggests device-detail navigation is driven by page JavaScript rather than ordinary anchor links.

## What is not done yet

- MAC extraction is not automated.
- The detail-page request path and the minimal extraction path for router-only metadata have not been reverse-engineered.

## Recommended next step

- Capture the authenticated device-detail navigation path for one known device where the MAC address is visible.
- Save any resulting HTML, JS hints, or request metadata under `agent/artifacts/router-admin-ingestion/`.
