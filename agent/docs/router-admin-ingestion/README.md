# Router Admin Ingestion

This epic establishes the durable Netwise home for authenticated router-admin ingestion work.
It is a real Netwise feature area, not a Maverick-only experiment.

## Initial target

- Xfinity gateway UI at `http://10.0.0.1`

## Product goal

Authenticate to local router admin pages and extract router-only device inventory data such as hostname, MAC address, connection type, band, RSSI, and related metadata that the scanner cannot reliably observe on its own.

This feature matters in two ways:

- it is a product capability in its own right
- it can provide ground-truth inputs that improve Netwise scanner discovery and labeling

## Durable layout

- `SUMMARY.md`
  - rolling epic summary and current state
- `discovery/`
  - dated discovery notes such as auth flow findings, page behavior, and next-step reversals
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\artifacts\router-admin-ingestion`
  - extracted router artifacts, redacted snapshots, and parser fixtures for this feature
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\internal\routeradmin`
  - future authenticated session, fetch, and extraction helpers
- `C:\Users\wimer\Desktop\Sentry\netwise\agent\internal\strategy\router_admin_*.go`
  - future strategy registration and scanner integration glue

## Control-plane split

- Maverick owns Discord routing, workstream creation, and channel/project plumbing.
- Netwise owns product-facing docs, durable feature notes, extracted artifacts, and implementation code.

## Naming conventions

- Maverick workstreams for this epic should use `router-admin-<target>-<slice>`.
- Discovery notes should use `YYYY-MM-DD-<target>-<topic>.md`.
- Artifacts should use `YYYY-MM-DD-<target>-<page>-<kind>.<ext>`.

Examples:

- `router-admin-xfinity-auth-flow`
- `router-admin-xfinity-device-detail`
- `2026-04-05-xfinity-gateway-baseline.md`
- `2026-04-05-xfinity-connected-devices-dom.html`

## Guardrails

- Ignore the public Xfinity site path for this epic unless a future task explicitly needs account-side data.
- Do not commit live credentials, cookies, or session tokens.
- Keep durable discovery updates in this epic folder even when the active workstream note lives in Maverick.
