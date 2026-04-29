# Router Admin Ingestion Summary

## Status

- Phase: authenticated Xfinity list-page scaffold
- Implementation: Go agent config/env plumbing, Xfinity login/list client, explicit-only `router_admin_inventory` strategy, and gated live test
- First target: Xfinity gateway UI at `http://10.0.0.1`

## Epic framing

- This is a real Netwise feature area, not just an experiment.
- The goal is authenticated ingestion of router-only device inventory data that complements scanner-derived evidence.
- The feature should eventually support both direct product value and scanner-improvement workflows.

## Confirmed discovery state

- The local router UI is reachable from the laptop.
- `http://10.0.0.1/index.jst` is the login page and posts to `check.jst`.
- The login form id observed during discovery is `pageForm`.
- The username field is `username`; the password field is `password`; the form also submits `locale=false`.
- The submit flow lowercases the username before submit.
- `http://10.0.0.1/connected_devices_computers.jst` requires authentication.
- Direct shell requests do not inherit the browser session, so authenticated client support is required for repeatable validation.
- The public Xfinity site was investigated by mistake early on and should be ignored for this feature path.
- In the authenticated router UI, the connected-device list is visible.
- Visible device entries previously observed include `Brooks`, `iPhone-83`, `eero`, multiple `AiDot` bulbs, `SonosZP`, `amazon-454178a7c`, and `L-H5CG3025X72`.
- Offline entries previously observed in the same UI include `raspberrypi4` and `XBOXONE`.
- Per-device entries on the list page are `javascript:void(0)` rather than normal links, so device-detail navigation is likely JS-driven.
- MAC extraction has not been automated yet.

## Implementation state

- Router-admin credentials are loaded from config and overridden by environment variables:
  - `NETWISE_ROUTER_ADMIN_URL`
  - `NETWISE_ROUTER_ADMIN_USERNAME`
  - `NETWISE_ROUTER_ADMIN_PASSWORD`
  - optional `NETWISE_ROUTER_ADMIN_PROVIDER`
  - optional `NETWISE_ROUTER_ADMIN_TIMEOUT_MS`
- `agent/internal/routeradmin/` contains the provider-selected client scaffold and the Xfinity login/list implementation.
- `router_admin_inventory` is registered as an explicit-only strategy. It is available when requested by name, but is excluded from `fast`, `medium`, default, and `full` strategy profiles.
- The strategy emits sanitized observations only: auth/list status, connected-device path, page title/hash/bytes, detail-path status/candidates, device count, and visible device names.
- Device-detail navigation and MAC extraction are intentionally out of scope for this slice.

## Validation

- Focused unit/regression target: `go test ./internal/routeradmin ./internal/strategy ./internal/config ./internal/scanner`
- Full agent regression target: `go test ./...`
- Gated live integration target: `NETWISE_ROUTER_ADMIN_LIVE=1 go test ./internal/routeradmin -run TestXfinityLiveCollect -v`
- The live test requires the router-admin env vars and passes only after login succeeds, the connected-device list page fetches, and at least one visible device label is collected.

## Next technical discovery step

- Capture one authenticated device-detail navigation sequence after login and save only the sanitized request path or path template under `agent/artifacts/router-admin-ingestion/`.
- Use that capture to extend the Xfinity client from list-page fetch into detail-page fetch and MAC extraction without hardcoding vendor-only markup assumptions.

## Durable update rule

- Update this file when the feature state changes materially.
- Add a dated note under `discovery/` for each meaningful discovery session so future workstreams can resume without re-learning the auth or page-flow context.
