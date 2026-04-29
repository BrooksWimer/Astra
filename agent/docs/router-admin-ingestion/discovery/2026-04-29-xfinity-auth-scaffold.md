# 2026-04-29 Xfinity Auth Scaffold

## Scope

This workstream implements the authenticated list-page scaffold only. It does not implement device-detail navigation or MAC extraction.

## Implemented flow

- `GET /index.jst` to confirm the Xfinity login form is present.
- `POST /check.jst` with `username`, `password`, and `locale=false`.
- `GET /connected_devices_computers.jst` with the authenticated cookie jar.

## Safe observations

The scaffold records only sanitized facts:

- provider and base URL
- auth/list status and status reason
- connected-device page path
- list-page title, SHA-1 hash, and byte count
- detail-path resolution status and candidate `.jst` paths
- connected-device count
- visible device names

Do not save passwords, cookies, raw router HTML, or unsanitized page dumps.

## Explicit-only strategy decision

`router_admin_inventory` is registered so a worker can run it by name, but it is marked explicit-only and excluded from `fast`, `medium`, default, and `full` strategy profiles. This keeps normal scans from logging into a household router until the ingestion surface is intentionally invoked.

## Next workstream

The next slice should capture an authenticated device-detail request path or path template, store only a sanitized request-shape artifact, then add detail-page MAC extraction behind the same explicit router-admin boundary.
