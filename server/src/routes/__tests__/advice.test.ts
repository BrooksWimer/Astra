import { afterAll, beforeAll, describe, test } from "vitest";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { createApp } from "../../app.js";

/**
 * HTTP-level integration tests for the /advice route handler.
 *
 * Layered above the unit tests in `src/advice/__tests__/`:
 *   - schema.test.ts → exercises adviceRequestSchema directly
 *   - engine.test.ts → exercises getAdvice() directly
 *   - this file     → exercises the wired Express route + JSON
 *                      parsing + error envelope shape
 *
 * Uses Node 20's built-in fetch against an ephemeral port; no
 * supertest dep needed.
 */
describe("/advice route", () => {
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

  const validRequest = {
    scan_id: "scan-1",
    device_id: "device-1",
    device: {
      id: "device-1",
      ip: "10.0.0.42",
      mac: "AA:BB:CC:DD:EE:FF",
      vendor: "ACME",
      hostname: null,
      protocols_seen: { mdns: [], ssdp: [], netbios: [] },
      first_seen: "2026-05-14T12:00:00Z",
      last_seen: "2026-05-14T12:05:00Z",
      flags: [],
      confidence: 0.5,
      device_type: "router",
    },
    network: {},
    user_context: "home",
  };

  test("POST /advice with valid body returns 200 + advice payload", async () => {
    const res = await fetch(`${baseUrl}/advice`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validRequest),
    });
    assert.equal(res.status, 200);
    const payload = (await res.json()) as {
      summary: string;
      risk_level: string;
      reasons: string[];
      actions: { title: string; urgency: string }[];
      uncertainty_notes: string[];
    };
    assert.match(payload.summary, /router/i);
    assert.ok(["medium", "high"].includes(payload.risk_level));
    assert.ok(payload.actions.some((a) => a.title === "Secure your router"));
  });

  test("POST /advice with missing scan_id returns 400 + Invalid request envelope", async () => {
    const { scan_id: _omit, ...withoutScanId } = validRequest;
    const res = await fetch(`${baseUrl}/advice`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(withoutScanId),
    });
    assert.equal(res.status, 400);
    const payload = (await res.json()) as { error: string; details: unknown };
    assert.equal(payload.error, "Invalid request");
    assert.ok(payload.details, "expected Zod error.flatten() output under details");
  });

  test("POST /advice with non-canonical device_type returns 400", async () => {
    const res = await fetch(`${baseUrl}/advice`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...validRequest,
        device: { ...validRequest.device, device_type: "smartfridge" },
      }),
    });
    assert.equal(res.status, 400);
  });

  test("POST /advice with speaker device_type returns 200 + speaker-specific action (regression for 7-vs-9 enum drift)", async () => {
    const res = await fetch(`${baseUrl}/advice`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...validRequest,
        device: { ...validRequest.device, device_type: "speaker" },
      }),
    });
    assert.equal(res.status, 200);
    const payload = (await res.json()) as { actions: { title: string }[] };
    assert.ok(payload.actions.some((a) => a.title === "Review voice-assistant privacy"));
  });

  test("POST /advice with camera device_type returns 200 + high risk", async () => {
    const res = await fetch(`${baseUrl}/advice`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...validRequest,
        device: { ...validRequest.device, device_type: "camera" },
      }),
    });
    assert.equal(res.status, 200);
    const payload = (await res.json()) as { risk_level: string; actions: { title: string }[] };
    assert.equal(payload.risk_level, "high");
    assert.ok(payload.actions.some((a) => a.title === "Lock down camera defaults"));
  });

  test("GET /health returns 200 + { status: 'ok' }", async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const payload = (await res.json()) as { status: string };
    assert.equal(payload.status, "ok");
  });

  test("POST /advice with non-JSON body returns 4xx (express.json() rejects)", async () => {
    const res = await fetch(`${baseUrl}/advice`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-actually-json-{",
    });
    assert.ok(res.status >= 400 && res.status < 500, `expected 4xx, got ${res.status}`);
  });

  test("POST /advice ignores the CORS preflight not being run (CORS just adds headers)", async () => {
    const res = await fetch(`${baseUrl}/advice`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validRequest),
    });
    assert.equal(res.headers.get("access-control-allow-origin"), "*");
  });
});
