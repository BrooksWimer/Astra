# Router Admin Package

This package contains the authenticated router-admin ingestion scaffold used by
the explicit `router_admin_inventory` strategy.

## Responsibilities

- load no secrets directly; callers pass env/config values in memory
- authenticate to supported router-admin UIs
- fetch only the connected-device list page in this slice
- return sanitized inventory observations: status, paths, page metadata/hash,
  detail-path candidates, device counts, and visible device names

## Xfinity scaffold

The current Xfinity provider performs this flow:

- `GET /index.jst`
- `POST /check.jst` with `username`, `password`, and `locale=false`
- `GET /connected_devices_computers.jst`

Device-detail navigation and MAC extraction are intentionally out of scope for
this workstream. Do not persist raw router HTML, cookies, passwords, or
unsanitized live captures.
