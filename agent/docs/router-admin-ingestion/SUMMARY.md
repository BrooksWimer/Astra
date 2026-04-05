# Router Admin Ingestion Summary

## Status

- Phase: discovery bootstrap
- Implementation: intentionally not started yet
- First target: Xfinity gateway UI at `http://10.0.0.1`

## Epic framing

- This is a real Netwise feature area, not just an experiment.
- The goal is authenticated ingestion of router-only device inventory data that complements scanner-derived evidence.
- The feature should eventually support both direct product value and scanner-improvement workflows.

## Confirmed discovery state

- The local router UI is reachable from the laptop.
- `http://10.0.0.1/index.jst` is the login page and posts to `check.jst`.
- `http://10.0.0.1/connected_devices_computers.jst` requires authentication.
- Direct shell requests do not inherit the browser session, so browser-session-based discovery has been necessary so far.
- The public Xfinity site was investigated by mistake early on and should be ignored for this feature path.
- In the authenticated router UI, the connected-device list is visible.
- Visible device entries include `Brooks`, `iPhone-83`, `eero`, multiple `AiDot` bulbs, `SonosZP`, `amazon-454178a7c`, and `L-H5CG3025X72`.
- Offline entries visible in the same UI include `raspberrypi4` and `XBOXONE`.
- The connected-devices page can be fetched from the logged-in browser session.
- Per-device entries on that page are `javascript:void(0)` rather than normal links, so device-detail navigation is likely JS-driven.
- MAC extraction has not been automated yet.

## Next technical discovery step

- Inspect the individual authenticated device-detail page where the MAC address is visible.
- Reverse-engineer the lightest reliable extraction path for that detail view before writing scraper code.

## Durable update rule

- Update this file when the feature state changes materially.
- Add a dated note under `discovery/` for each meaningful discovery session so future workstreams can resume without re-learning the auth or page-flow context.
