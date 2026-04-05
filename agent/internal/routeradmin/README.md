# Router Admin Package Placeholder

This directory is reserved for future router-admin-ingestion implementation.

## Intended responsibilities

- authenticated router-session helpers
- page fetch and parse helpers
- target-specific extraction logic for router-only metadata
- shared types used by router-admin ingestion code

## Integration boundary

- Keep scanner strategy registration in `agent/internal/strategy/` using `router_admin_*.go` files when implementation starts.
- Keep durable feature notes in `agent/docs/router-admin-ingestion/`.
- Keep extracted fixtures and captured page artifacts in `agent/artifacts/router-admin-ingestion/`.

## Current state

Docs only. No scraping logic has been implemented here yet.
