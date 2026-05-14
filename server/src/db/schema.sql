-- Astra server persistence layer
--
-- All data is keyed by an anonymous handle (a per-install UUID the client
-- generates and reuses across requests). No account model in V1; the handle
-- is the identity. This lets a mobile + desktop pair sync via a shared
-- handle without anyone ever creating an account.

CREATE TABLE IF NOT EXISTS scans (
  id              TEXT PRIMARY KEY,
  handle          TEXT NOT NULL,
  network_json    TEXT NOT NULL,            -- JSON-encoded NetworkInfo
  device_count    INTEGER NOT NULL,
  scan_started_at TEXT NOT NULL,            -- ISO 8601
  scan_finished_at TEXT,                    -- ISO 8601, nullable
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scans_handle_created
  ON scans(handle, created_at DESC);

CREATE TABLE IF NOT EXISTS scan_devices (
  scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  device_id   TEXT NOT NULL,
  device_json TEXT NOT NULL,                -- full Device JSON
  PRIMARY KEY (scan_id, device_id)
);

-- Per-handle device labels. Stored separately from scan_devices so a user's
-- naming persists across scans even if the device disappears + reappears.
CREATE TABLE IF NOT EXISTS device_labels (
  handle      TEXT NOT NULL,
  device_id   TEXT NOT NULL,                -- typically the MAC address
  label       TEXT,                         -- operator-given nickname
  notes       TEXT,                         -- free-form operator notes
  source      TEXT NOT NULL DEFAULT 'mobile', -- 'mobile' | 'desktop' | 'auto'
  updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (handle, device_id)
);

CREATE INDEX IF NOT EXISTS idx_device_labels_handle
  ON device_labels(handle);
