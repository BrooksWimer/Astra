/**
 * Per-handle device-label persistence.
 *
 * Stored separately from scan_devices so that a user's naming, notes, and
 * source attribution survive across scans — even if a device drops off the
 * network and reappears later (different IP, same MAC), the label persists.
 *
 * "Source" is one of: 'mobile' | 'desktop' | 'auto'. The auto source is
 * reserved for label suggestions the agent infers from scanner evidence
 * (vendor + hostname + protocols); today's writes are only 'mobile' or
 * 'desktop' from operator actions.
 */

import { getDb } from "../db/index.js";

export type LabelSource = "mobile" | "desktop" | "auto";

export interface StoredLabel {
  handle: string;
  deviceId: string;
  label: string | null;
  notes: string | null;
  source: LabelSource;
  updatedAt: string;
}

export interface UpsertLabelInput {
  handle: string;
  deviceId: string;
  label?: string | null;
  notes?: string | null;
  source: LabelSource;
}

interface LabelRow {
  handle: string;
  device_id: string;
  label: string | null;
  notes: string | null;
  source: LabelSource;
  updated_at: string;
}

export function upsertLabel(input: UpsertLabelInput): StoredLabel {
  const db = getDb();
  db.prepare(
    `INSERT INTO device_labels (handle, device_id, label, notes, source, updated_at)
     VALUES (@handle, @device_id, @label, @notes, @source, datetime('now'))
     ON CONFLICT(handle, device_id) DO UPDATE SET
       label = excluded.label,
       notes = excluded.notes,
       source = excluded.source,
       updated_at = excluded.updated_at`,
  ).run({
    handle: input.handle,
    device_id: input.deviceId,
    label: input.label ?? null,
    notes: input.notes ?? null,
    source: input.source,
  });

  const stored = getLabel(input.handle, input.deviceId);
  if (!stored) {
    throw new Error(
      `Label (${input.handle}, ${input.deviceId}) not retrievable immediately after upsert`,
    );
  }
  return stored;
}

export function getLabel(handle: string, deviceId: string): StoredLabel | null {
  const db = getDb();
  const row = db
    .prepare("SELECT * FROM device_labels WHERE handle = ? AND device_id = ?")
    .get(handle, deviceId) as LabelRow | undefined;
  if (!row) return null;
  return hydrate(row);
}

export function listLabelsForHandle(handle: string): StoredLabel[] {
  const db = getDb();
  const rows = db
    .prepare("SELECT * FROM device_labels WHERE handle = ? ORDER BY updated_at DESC")
    .all(handle) as LabelRow[];
  return rows.map(hydrate);
}

export function deleteLabel(handle: string, deviceId: string): boolean {
  const db = getDb();
  const result = db
    .prepare("DELETE FROM device_labels WHERE handle = ? AND device_id = ?")
    .run(handle, deviceId);
  return result.changes > 0;
}

function hydrate(row: LabelRow): StoredLabel {
  return {
    handle: row.handle,
    deviceId: row.device_id,
    label: row.label,
    notes: row.notes,
    source: row.source,
    updatedAt: row.updated_at,
  };
}
