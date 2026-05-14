import { afterEach, beforeEach, describe, test } from "vitest";
import assert from "node:assert/strict";

import { closeDb, openDb } from "../../db/index.js";
import { getLatestScanForHandle, getScanById, saveScan } from "../store.js";

const HANDLE_A = "11111111-1111-4111-8111-111111111111";
const HANDLE_B = "22222222-2222-4222-8222-222222222222";

const SAMPLE_DEVICE = {
  id: "AA:BB:CC:DD:EE:01",
  ip: "10.0.0.5",
  mac: "AA:BB:CC:DD:EE:01",
  vendor: "ACME",
  hostname: null,
  protocols_seen: { mdns: [], ssdp: [], netbios: [] },
  first_seen: "2026-05-14T12:00:00Z",
  last_seen: "2026-05-14T12:05:00Z",
  flags: [],
  confidence: 0.5,
  device_type: "router" as const,
};

describe("scans store", () => {
  beforeEach(() => {
    openDb({ path: ":memory:" });
  });

  afterEach(() => {
    closeDb();
  });

  test("saveScan inserts a scan + its devices and returns the hydrated row", () => {
    const stored = saveScan({
      handle: HANDLE_A,
      network: { subnet: "10.0.0.0/24", gateway_ip: "10.0.0.1" },
      devices: [SAMPLE_DEVICE],
      scanStartedAt: "2026-05-14T12:00:00Z",
      scanFinishedAt: "2026-05-14T12:00:05Z",
    });

    assert.ok(stored.id);
    assert.equal(stored.handle, HANDLE_A);
    assert.equal(stored.devices.length, 1);
    assert.equal(stored.devices[0].mac, SAMPLE_DEVICE.mac);
    assert.equal(stored.scanStartedAt, "2026-05-14T12:00:00Z");
    assert.equal(stored.scanFinishedAt, "2026-05-14T12:00:05Z");
  });

  test("getScanById hydrates devices in order, returns null when missing", () => {
    const stored = saveScan({
      handle: HANDLE_A,
      network: {},
      devices: [
        { ...SAMPLE_DEVICE, id: "AA:BB:CC:DD:EE:02", mac: "AA:BB:CC:DD:EE:02" },
        { ...SAMPLE_DEVICE, id: "AA:BB:CC:DD:EE:01" },
      ],
      scanStartedAt: "2026-05-14T12:00:00Z",
    });

    const fetched = getScanById(stored.id);
    assert.ok(fetched);
    assert.equal(fetched.devices.length, 2);
    // ORDER BY device_id ASC → 01 before 02
    assert.equal(fetched.devices[0].id, "AA:BB:CC:DD:EE:01");
    assert.equal(fetched.devices[1].id, "AA:BB:CC:DD:EE:02");

    assert.equal(getScanById("does-not-exist"), null);
  });

  test("scanFinishedAt is optional and persists as null", () => {
    const stored = saveScan({
      handle: HANDLE_A,
      network: {},
      devices: [SAMPLE_DEVICE],
      scanStartedAt: "2026-05-14T12:00:00Z",
    });
    assert.equal(stored.scanFinishedAt, null);
    const reloaded = getScanById(stored.id);
    assert.equal(reloaded!.scanFinishedAt, null);
  });

  test("getLatestScanForHandle returns the most-recently-inserted scan", async () => {
    const first = saveScan({
      handle: HANDLE_A,
      network: {},
      devices: [SAMPLE_DEVICE],
      scanStartedAt: "2026-05-14T12:00:00Z",
    });
    // SQLite resolution is seconds with datetime('now'); space saves to avoid
    // the same-second tie (the store ORDER BY also includes `id DESC` as a
    // tiebreaker, but waiting makes the test deterministic).
    await new Promise((r) => setTimeout(r, 1100));
    const second = saveScan({
      handle: HANDLE_A,
      network: {},
      devices: [SAMPLE_DEVICE],
      scanStartedAt: "2026-05-14T12:10:00Z",
    });

    const latest = getLatestScanForHandle(HANDLE_A);
    assert.ok(latest);
    assert.equal(latest.id, second.id);
    assert.notEqual(latest.id, first.id);
  });

  test("getLatestScanForHandle returns null when handle has no scans", () => {
    assert.equal(getLatestScanForHandle(HANDLE_A), null);
  });

  test("handles are scoped: handle B doesn't see handle A's scans", () => {
    saveScan({
      handle: HANDLE_A,
      network: {},
      devices: [SAMPLE_DEVICE],
      scanStartedAt: "2026-05-14T12:00:00Z",
    });
    assert.equal(getLatestScanForHandle(HANDLE_B), null);
  });
});
