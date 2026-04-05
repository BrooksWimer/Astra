# Router Admin Ingestion Artifacts

Use this folder for durable extracted artifacts that support the router-admin-ingestion epic.

## Expected contents

- redacted HTML snapshots
- DOM text extracts
- JS snippets or deobfuscated page-flow notes
- request and response shape notes
- parser fixtures derived from authenticated pages

## File naming

- `YYYY-MM-DD-<target>-<page>-<kind>.<ext>`

Examples:

- `2026-04-05-xfinity-connected-devices-dom.html`
- `2026-04-05-xfinity-device-detail-request.txt`

## Safety rules

- Never commit live passwords, cookies, or session tokens.
- Prefer redacted fixtures when raw captures contain sensitive household data.
- If an artifact is too sensitive to commit, record the finding in a discovery note and describe what was redacted or withheld.
