/**
 * Persistence layer for scans + scan_devices.
 *
 * A scan is an atomic snapshot of a network as seen by the Go agent (or the
 * mobile app's limited-on-device scanner). The mobile/desktop client POSTs
 * the full {network, devices, scan_started_at, scan_finished_at} payload
 * and the server stores it keyed by the install's anonymous handle.
 *
 * Each row is JSON-encoded so additions to Device / NetworkInfo in
 * shared/schema.json don't require a schema migration on the server side
 * — the shape is validated by Zod at the route layer, then stored as a
 * blob here.
 */

import { randomUUID } from "node:crypto";
import type { Device, NetworkInfo } from "@netwise/shared";

import { getDb } from "../db/index.js";

export interface StoredScan {
  id: string;
  handle: string;
  network: NetworkInfo;
  devices: Device[];
  scanStartedAt: string;
  scanFinishedAt: string | null;
  createdAt: string;
}

export interface SaveScanInput {
  handle: string;
  network: NetworkInfo;
  devices: Device[];
  scanStartedAt: string;
  scanFinishedAt?: string | null;
}

interface ScanRow {
  id: string;
  handle: string;
  network_json: string;
  device_count: number;
  scan_started_at: string;
  scan_finished_at: string | null;
  created_at: string;
}

interface ScanDeviceRow {
  scan_id: string;
  device_id: string;
  device_json: string;
}

export function saveScan(input: SaveScanInput): StoredScan {
  const db = getDb();
  const id = randomUUID();

  const tx = db.transaction((scan: SaveScanInput) => {
    db.prepare(
      `INSERT INTO scans
       (id, handle, network_json, device_count, scan_started_at, scan_finished_at)
       VALUES (@id, @handle, @network_json, @device_count, @scan_started_at, @scan_finished_at)`,
    ).run({
      id,
      handle: scan.handle,
      network_json: JSON.stringify(scan.network),
      device_count: scan.devices.length,
      scan_started_at: scan.scanStartedAt,
      scan_finished_at: scan.scanFinishedAt ?? null,
    });

    const insertDevice = db.prepare(
      `INSERT INTO scan_devices (scan_id, device_id, device_json)
       VALUES (?, ?, ?)`,
    );
    for (const device of scan.devices) {
      insertDevice.run(id, device.id, JSON.stringify(device));
    }
  });

  tx(input);

  const stored = getScanById(id);
  if (!stored) {
    // Defensive: shouldn't happen since we just inserted. Throw rather than
    // returning a confidently-wrong shape.
    throw new Error(`Scan ${id} not retrievable immediately after insert`);
  }
  return stored;
}

export function getScanById(id: string): StoredScan | null {
  const db = getDb();
  const row = db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as ScanRow | undefined;
  if (!row) return null;
  return hydrate(row);
}

/**
 * Returns the latest scan stored for `handle`, or null if the handle has no
 * scans. Latest = largest `created_at` (the index makes this fast).
 */
export function getLatestScanForHandle(handle: string): StoredScan | null {
  const db = getDb();
  const row = db
    .prepare(
      `SELECT * FROM scans
       WHERE handle = ?
       ORDER BY created_at DESC, id DESC
       LIMIT 1`,
    )
    .get(handle) as ScanRow | undefined;
  if (!row) return null;
  return hydrate(row);
}

function hydrate(row: ScanRow): StoredScan {
  const db = getDb();
  const deviceRows = db
    .prepare("SELECT * FROM scan_devices WHERE scan_id = ? ORDER BY device_id ASC")
    .all(row.id) as ScanDeviceRow[];
  return {
    id: row.id,
    handle: row.handle,
    network: JSON.parse(row.network_json) as NetworkInfo,
    devices: deviceRows.map((d) => JSON.parse(d.device_json) as Device),
    scanStartedAt: row.scan_started_at,
    scanFinishedAt: row.scan_finished_at,
    createdAt: row.created_at,
  };
}
