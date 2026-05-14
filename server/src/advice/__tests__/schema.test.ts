import { test } from "node:test";
import assert from "node:assert/strict";

import { adviceRequestSchema } from "../schema.js";

/**
 * Validation contract for the /advice POST body. These tests pin the
 * fields where the schema and shared/schema.json have historically drifted:
 *
 *  - hostname is NOT in the JSON schema's required[] list, so the field
 *    may be absent entirely (undefined), present as null when no hostname
 *    was resolved, or present as a real string. Server-side type-check
 *    against the shared `Device` interface broke when the interface
 *    modeled hostname as `string | null` (no undefined).
 *  - device_type's canonical enum is 9 values. The Zod enum had drifted
 *    to 7, missing "speaker" and "camera", which would 400 any /advice
 *    request for a discovered speaker or IP camera.
 */

const baseDevice = {
  id: "device-1",
  ip: "10.0.0.42",
  mac: "AA:BB:CC:DD:EE:FF",
  vendor: "ACME",
  protocols_seen: { mdns: [], ssdp: [], netbios: [] },
  first_seen: "2026-05-14T12:00:00Z",
  last_seen: "2026-05-14T12:05:00Z",
  flags: [],
  confidence: 0.5,
  device_type: "router" as const,
};

function baseRequest(overrides: Partial<{ device: typeof baseDevice }> = {}) {
  return {
    scan_id: "scan-1",
    device_id: "device-1",
    device: overrides.device ?? baseDevice,
    network: {},
    user_context: "home" as const,
  };
}

test("accepts a device with no hostname field at all (omitted, undefined)", () => {
  const result = adviceRequestSchema.safeParse(baseRequest());
  assert.equal(result.success, true);
});

test("accepts a device with hostname: null", () => {
  const result = adviceRequestSchema.safeParse(
    baseRequest({ device: { ...baseDevice, hostname: null } as any }),
  );
  assert.equal(result.success, true);
});

test("accepts a device with hostname: <string>", () => {
  const result = adviceRequestSchema.safeParse(
    baseRequest({ device: { ...baseDevice, hostname: "router.local" } as any }),
  );
  assert.equal(result.success, true);
});

test("accepts every canonical device_type", () => {
  const canonicalTypes = [
    "phone",
    "laptop",
    "router",
    "printer",
    "tv",
    "speaker",
    "camera",
    "iot",
    "unknown",
  ];
  for (const dt of canonicalTypes) {
    const result = adviceRequestSchema.safeParse(
      baseRequest({ device: { ...baseDevice, device_type: dt } as any }),
    );
    assert.equal(result.success, true, `device_type "${dt}" should be accepted`);
  }
});

test("rejects an unknown device_type that is not in the canonical 9-value enum", () => {
  const result = adviceRequestSchema.safeParse(
    baseRequest({ device: { ...baseDevice, device_type: "smartfridge" } as any }),
  );
  assert.equal(result.success, false);
});

test("rejects a missing required top-level field (scan_id)", () => {
  const { scan_id: _omit, ...without } = baseRequest();
  const result = adviceRequestSchema.safeParse(without);
  assert.equal(result.success, false);
});

test("rejects an invalid user_context", () => {
  const req = baseRequest();
  const result = adviceRequestSchema.safeParse({ ...req, user_context: "datacenter" });
  assert.equal(result.success, false);
});

test("rejects a confidence outside [0, 1]", () => {
  const result = adviceRequestSchema.safeParse(
    baseRequest({ device: { ...baseDevice, confidence: 1.5 } as any }),
  );
  assert.equal(result.success, false);
});

test("fills protocols_seen defaults when arrays are omitted", () => {
  const deviceWithoutProtocols: any = { ...baseDevice };
  deviceWithoutProtocols.protocols_seen = {};
  const parsed = adviceRequestSchema.safeParse(
    baseRequest({ device: deviceWithoutProtocols }),
  );
  assert.equal(parsed.success, true);
  if (parsed.success) {
    assert.deepEqual(parsed.data.device.protocols_seen.mdns, []);
    assert.deepEqual(parsed.data.device.protocols_seen.ssdp, []);
    assert.deepEqual(parsed.data.device.protocols_seen.netbios, []);
  }
});
