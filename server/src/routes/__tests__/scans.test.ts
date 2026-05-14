import { afterAll, afterEach, beforeAll, beforeEach, describe, test } from "vitest";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { createApp } from "../../app.js";
import { closeDb, openDb } from "../../db/index.js";

const HANDLE_A = "33333333-3333-4333-8333-333333333333";
const HANDLE_B = "44444444-4444-4444-8444-444444444444";

const SAMPLE_DEVICE = {
  id: "AA:BB:CC:DD:EE:F1",
  ip: "10.0.0.5",
  mac: "AA:BB:CC:DD:EE:F1",
  vendor: "ACME",
  hostname: null,
  protocols_seen: { mdns: [], ssdp: [], netbios: [] },
  first_seen: "2026-05-14T12:00:00Z",
  last_seen: "2026-05-14T12:05:00Z",
  flags: [],
  confidence: 0.5,
  device_type: "camera",
};

const VALID_SCAN_BODY = {
  network: { subnet: "10.0.0.0/24", gateway_ip: "10.0.0.1" },
  devices: [SAMPLE_DEVICE],
  scan_started_at: "2026-05-14T12:00:00Z",
  scan_finished_at: "2026-05-14T12:00:05Z",
};

describe("/scans routes", () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    const app = createApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => resolve());
    });
    const port = (server.address() as AddressInfo).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => {
    openDb({ path: ":memory:" });
  });

  afterEach(() => {
    closeDb();
  });

  test("POST /scans with valid handle + body → 201 + id", async () => {
    const res = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify(VALID_SCAN_BODY),
    });
    assert.equal(res.status, 201);
    const payload = (await res.json()) as {
      id: string;
      handle: string;
      device_count: number;
    };
    assert.ok(payload.id);
    assert.equal(payload.handle, HANDLE_A);
    assert.equal(payload.device_count, 1);
  });

  test("POST /scans without a handle → 400 with missing-handle envelope", async () => {
    const res = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_SCAN_BODY),
    });
    assert.equal(res.status, 400);
    const payload = (await res.json()) as { error: string };
    assert.match(payload.error, /Missing or invalid handle/);
  });

  test("POST /scans with a non-UUIDv4 handle → 400", async () => {
    const res = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": "not-a-uuid",
      },
      body: JSON.stringify(VALID_SCAN_BODY),
    });
    assert.equal(res.status, 400);
  });

  test("POST /scans with malformed body → 400 + Invalid scan payload", async () => {
    const res = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify({ devices: "not-an-array" }),
    });
    assert.equal(res.status, 400);
    const payload = (await res.json()) as { error: string };
    assert.match(payload.error, /Invalid scan payload/);
  });

  test("GET /scans/:id returns the scan when the handle matches", async () => {
    const post = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify(VALID_SCAN_BODY),
    });
    const created = (await post.json()) as { id: string };

    const get = await fetch(`${baseUrl}/scans/${created.id}`, {
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    assert.equal(get.status, 200);
    const scan = (await get.json()) as {
      id: string;
      handle: string;
      devices: { device_type: string }[];
    };
    assert.equal(scan.id, created.id);
    assert.equal(scan.handle, HANDLE_A);
    assert.equal(scan.devices.length, 1);
    assert.equal(scan.devices[0].device_type, "camera");
  });

  test("GET /scans/:id returns 404 when the requesting handle doesn't own it", async () => {
    const post = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify(VALID_SCAN_BODY),
    });
    const created = (await post.json()) as { id: string };

    const get = await fetch(`${baseUrl}/scans/${created.id}`, {
      headers: { "X-Astra-Handle": HANDLE_B },
    });
    // Same error as not-found; we don't leak existence to other handles.
    assert.equal(get.status, 404);
  });

  test("GET /scans/latest returns the most recent scan for the handle", async () => {
    await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Astra-Handle": HANDLE_A },
      body: JSON.stringify(VALID_SCAN_BODY),
    });
    await new Promise((r) => setTimeout(r, 1100));
    const second = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Astra-Handle": HANDLE_A },
      body: JSON.stringify({
        ...VALID_SCAN_BODY,
        scan_started_at: "2026-05-14T12:10:00Z",
      }),
    });
    const secondCreated = (await second.json()) as { id: string };

    const latest = await fetch(`${baseUrl}/scans/latest?handle=${HANDLE_A}`);
    assert.equal(latest.status, 200);
    const latestScan = (await latest.json()) as { id: string };
    assert.equal(latestScan.id, secondCreated.id);
  });

  test("GET /scans/latest returns 404 when handle has no scans", async () => {
    const res = await fetch(`${baseUrl}/scans/latest?handle=${HANDLE_A}`);
    assert.equal(res.status, 404);
  });

  test("POST /scans/:id/advice returns per-device + network insight", async () => {
    const post = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify(VALID_SCAN_BODY),
    });
    const created = (await post.json()) as { id: string };

    const advice = await fetch(`${baseUrl}/scans/${created.id}/advice`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify({ user_context: "home" }),
    });
    assert.equal(advice.status, 200);
    const payload = (await advice.json()) as {
      scan_id: string;
      device_count: number;
      devices: { device_id: string; advice: { risk_level: string } }[];
      network: {
        deviceCount: number;
        riskLevel: string;
        insights: { id: string; severity: string }[];
      };
    };
    assert.equal(payload.scan_id, created.id);
    assert.equal(payload.devices.length, 1);
    assert.equal(payload.devices[0].advice.risk_level, "high"); // camera
    assert.equal(payload.network.deviceCount, 1);
    assert.equal(payload.network.riskLevel, "high"); // camera triggers it
    assert.ok(payload.network.insights.some((i) => i.id === "cameras-present"));
  });

  test("POST /scans/:id/advice on non-existent scan → 404", async () => {
    const advice = await fetch(`${baseUrl}/scans/does-not-exist/advice`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify({}),
    });
    assert.equal(advice.status, 404);
  });

  test("POST /scans/:id/advice with invalid user_context → 400", async () => {
    const post = await fetch(`${baseUrl}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify(VALID_SCAN_BODY),
    });
    const created = (await post.json()) as { id: string };

    const advice = await fetch(`${baseUrl}/scans/${created.id}/advice`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Astra-Handle": HANDLE_A,
      },
      body: JSON.stringify({ user_context: "datacenter" }),
    });
    assert.equal(advice.status, 400);
  });
});
