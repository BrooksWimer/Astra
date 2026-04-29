# Router Admin Ingestion Artifacts

Use this folder for durable, sanitized artifacts that support the router-admin-ingestion epic.

## Allowed contents

- HTTP status codes and request method/path shapes
- page titles, byte counts, and content hashes
- visible device names
- redacted form-field names and path templates
- sanitized detail-path candidates

## Forbidden contents

- passwords or password-derived values
- cookies, session IDs, CSRF tokens, or bearer tokens
- raw router HTML
- raw browser storage, HAR files, or unsanitized page dumps
- household network captures that include device MACs before the MAC-extraction slice is explicitly approved

## File naming

- `YYYY-MM-DD-<target>-<page>-<kind>.<ext>`

Examples:

- `2026-04-29-xfinity-auth-request-shapes.txt`
- `2026-04-29-xfinity-device-detail-request-shape.txt`

If an artifact is too sensitive to commit, record only the sanitized finding in a discovery note and describe what was withheld.
