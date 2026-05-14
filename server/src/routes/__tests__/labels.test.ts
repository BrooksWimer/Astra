import { afterAll, afterEach, beforeAll, beforeEach, describe, test } from "vitest";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { createApp } from "../../app.js";
import { closeDb, openDb } from "../../db/index.js";

const HANDLE_A = "77777777-7777-4777-8777-777777777777";
const HANDLE_B = "88888888-8888-4888-8888-888888888888";

describe("/labels routes", () => {
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

  async function putLabel(handle: string, body: Record<string, unknown>) {
    return fetch(`${baseUrl}/labels`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-Astra-Handle": handle },
      body: JSON.stringify(body),
    });
  }

  test("PUT /labels with valid body → 200 + stored payload", async () => {
    const res = await putLabel(HANDLE_A, {
      device_id: "AA:BB:CC:DD:EE:01",
      label: "Living-room TV",
      notes: "Vizio",
      source: "mobile",
    });
    assert.equal(res.status, 200);
    const payload = (await res.json()) as {
      handle: string;
      deviceId: string;
      label: string;
      notes: string;
      source: string;
    };
    assert.equal(payload.handle, HANDLE_A);
    assert.equal(payload.deviceId, "AA:BB:CC:DD:EE:01");
    assert.equal(payload.label, "Living-room TV");
    assert.equal(payload.source, "mobile");
  });

  test("PUT /labels defaults source to 'mobile' when omitted", async () => {
    const res = await putLabel(HANDLE_A, {
      device_id: "AA:BB:CC:DD:EE:01",
      label: "TV",
    });
    assert.equal(res.status, 200);
    const payload = (await res.json()) as { source: string };
    assert.equal(payload.source, "mobile");
  });

  test("PUT /labels rejects an unknown source enum", async () => {
    const res = await putLabel(HANDLE_A, {
      device_id: "AA:BB:CC:DD:EE:01",
      label: "TV",
      source: "telegram",
    });
    assert.equal(res.status, 400);
  });

  test("PUT /labels without a handle → 400", async () => {
    const res = await fetch(`${baseUrl}/labels`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: "AA", label: "TV" }),
    });
    assert.equal(res.status, 400);
    const payload = (await res.json()) as { error: string };
    assert.match(payload.error, /Missing or invalid handle/);
  });

  test("PUT /labels with empty device_id → 400", async () => {
    const res = await putLabel(HANDLE_A, { device_id: "", label: "TV" });
    assert.equal(res.status, 400);
  });

  test("GET /labels returns all labels for the handle, recently-updated first", async () => {
    await putLabel(HANDLE_A, { device_id: "AA:BB:CC:DD:EE:01", label: "First" });
    await new Promise((r) => setTimeout(r, 1100));
    await putLabel(HANDLE_A, { device_id: "AA:BB:CC:DD:EE:02", label: "Second" });

    const res = await fetch(`${baseUrl}/labels`, {
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    assert.equal(res.status, 200);
    const payload = (await res.json()) as {
      handle: string;
      count: number;
      labels: { label: string }[];
    };
    assert.equal(payload.count, 2);
    assert.equal(payload.labels[0].label, "Second");
    assert.equal(payload.labels[1].label, "First");
  });

  test("GET /labels returns empty list for handle with no labels", async () => {
    const res = await fetch(`${baseUrl}/labels`, {
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    assert.equal(res.status, 200);
    const payload = (await res.json()) as { count: number; labels: unknown[] };
    assert.equal(payload.count, 0);
    assert.deepEqual(payload.labels, []);
  });

  test("GET /labels/:deviceId returns the label", async () => {
    await putLabel(HANDLE_A, {
      device_id: "AA:BB:CC:DD:EE:01",
      label: "TV",
    });
    const res = await fetch(`${baseUrl}/labels/AA:BB:CC:DD:EE:01`, {
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    assert.equal(res.status, 200);
    const payload = (await res.json()) as { label: string };
    assert.equal(payload.label, "TV");
  });

  test("GET /labels/:deviceId returns 404 when missing", async () => {
    const res = await fetch(`${baseUrl}/labels/AA:BB:CC:DD:EE:01`, {
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    assert.equal(res.status, 404);
  });

  test("handle scoping: GET /labels for HANDLE_B doesn't see HANDLE_A's labels", async () => {
    await putLabel(HANDLE_A, { device_id: "AA:BB:CC:DD:EE:01", label: "TV" });
    const res = await fetch(`${baseUrl}/labels`, {
      headers: { "X-Astra-Handle": HANDLE_B },
    });
    const payload = (await res.json()) as { count: number };
    assert.equal(payload.count, 0);
  });

  test("DELETE /labels/:deviceId removes the label, returns 204", async () => {
    await putLabel(HANDLE_A, { device_id: "AA:BB:CC:DD:EE:01", label: "TV" });

    const res = await fetch(`${baseUrl}/labels/AA:BB:CC:DD:EE:01`, {
      method: "DELETE",
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    assert.equal(res.status, 204);

    const after = await fetch(`${baseUrl}/labels/AA:BB:CC:DD:EE:01`, {
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    assert.equal(after.status, 404);
  });

  test("DELETE on a missing label → 404 (idempotent semantic, but explicit)", async () => {
    const res = await fetch(`${baseUrl}/labels/AA:BB:CC:DD:EE:01`, {
      method: "DELETE",
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    assert.equal(res.status, 404);
  });

  test("upsert via PUT: second PUT updates the same row in place", async () => {
    await putLabel(HANDLE_A, {
      device_id: "AA:BB:CC:DD:EE:01",
      label: "TV",
      source: "mobile",
    });
    const second = await putLabel(HANDLE_A, {
      device_id: "AA:BB:CC:DD:EE:01",
      label: "Living-room TV",
      source: "desktop",
    });
    assert.equal(second.status, 200);

    const list = await fetch(`${baseUrl}/labels`, {
      headers: { "X-Astra-Handle": HANDLE_A },
    });
    const payload = (await list.json()) as {
      count: number;
      labels: { label: string; source: string }[];
    };
    assert.equal(payload.count, 1);
    assert.equal(payload.labels[0].label, "Living-room TV");
    assert.equal(payload.labels[0].source, "desktop");
  });
});
