# Astra / Netwise Project Context

Astra is the public-facing product name. Netwise is the internal repo/config name.

## Product Identity

Astra is a home-network intelligence app for ordinary home network users who want to discover, label, and understand the devices on their Wi-Fi/LAN without being network experts.

## Current System Shape

- `agent/`: Go LAN scanner, strategy system, CLI, reports, and scanner research.
- `mobile/`: Expo / React Native mobile client.
- `server/`: Node/Express advice and assistant APIs.
- `shared/`: shared schemas and TypeScript types.

## Epics

- `laptop-wifi-scanner`: laptop/desktop Go scanner and labeling research.
- `mobile-wifi-scanner`: mobile app scanning and iOS feasibility.
- `router-admin-ingestion`: authenticated router admin data ingestion.

## Planning Rules

- Use Astra in public portfolio/product context.
- Use Netwise for repo paths, packages, and internal orchestration references.
- Treat scanner research as product support, not the whole product identity.
- Do not overclaim scanner accuracy without evidence from tests, reports, or live runs.

## TODO

- Add current best scanner strategy summary.
- Add mobile feasibility status.
- Add router-ingestion discovery notes beyond the existing strategy catalog pointer.
