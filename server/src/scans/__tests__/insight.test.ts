import { describe, test } from "vitest";
import assert from "node:assert/strict";
import type { Device } from "@netwise/shared";

import { summarizeNetwork } from "../insight.js";

function makeDevice(overrides: Partial<Device> = {}): Device {
  return {
    id: overrides.id ?? overrides.mac ?? "00:00:00:00:00:01",
    ip: "10.0.0.10",
    mac: overrides.id ?? "00:00:00:00:00:01",
    vendor: "ACME",
    hostname: null,
    protocols_seen: { mdns: [], ssdp: [], netbios: [] },
    first_seen: "2026-05-14T12:00:00Z",
    last_seen: "2026-05-14T12:05:00Z",
    flags: [],
    confidence: 0.5,
    device_type: "unknown",
    ...overrides,
  };
}

describe("summarizeNetwork", () => {
  test("empty scan → no insights, low risk, zero devices", () => {
    const report = summarizeNetwork([]);
    assert.equal(report.deviceCount, 0);
    assert.equal(report.insights.length, 0);
    assert.equal(report.riskLevel, "low");
    assert.deepEqual(report.byDeviceType, {});
  });

  test("camera present → critical 'cameras-present' insight + high risk", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "cam-1", device_type: "camera" }),
    ]);
    const camera = report.insights.find((i) => i.id === "cameras-present");
    assert.ok(camera, "expected cameras-present insight");
    assert.equal(camera.severity, "critical");
    assert.deepEqual(camera.evidence, ["cam-1"]);
    assert.equal(report.riskLevel, "high");
  });

  test("multiple cameras → singular vs plural title", () => {
    const single = summarizeNetwork([makeDevice({ id: "cam-1", device_type: "camera" })]);
    assert.match(
      single.insights.find((i) => i.id === "cameras-present")!.title,
      /^A network camera/,
    );

    const several = summarizeNetwork([
      makeDevice({ id: "cam-1", device_type: "camera" }),
      makeDevice({ id: "cam-2", device_type: "camera" }),
    ]);
    assert.match(
      several.insights.find((i) => i.id === "cameras-present")!.title,
      /^2 network cameras/,
    );
  });

  test("3+ IoT devices → warn 'iot-density' insight + medium risk", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "iot-1", device_type: "iot" }),
      makeDevice({ id: "iot-2", device_type: "iot" }),
      makeDevice({ id: "iot-3", device_type: "iot" }),
    ]);
    const density = report.insights.find((i) => i.id === "iot-density");
    assert.ok(density);
    assert.equal(density.severity, "warn");
    assert.deepEqual(density.evidence.sort(), ["iot-1", "iot-2", "iot-3"]);
    assert.equal(report.riskLevel, "medium");
  });

  test("2 IoT devices → no iot-density insight (threshold is 3)", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "iot-1", device_type: "iot" }),
      makeDevice({ id: "iot-2", device_type: "iot" }),
    ]);
    assert.ok(!report.insights.some((i) => i.id === "iot-density"));
    // Still medium because each IoT device is a risk in itself... but we
    // don't bump from any single IoT. Roll-up should be low.
    assert.equal(report.riskLevel, "low");
  });

  test("device with SMB (445) port open → smb-rdp-exposure warn", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "host-1", device_type: "laptop", ports_open: [445] }),
    ]);
    const expo = report.insights.find((i) => i.id === "smb-rdp-exposure");
    assert.ok(expo);
    assert.equal(expo.severity, "warn");
    assert.deepEqual(expo.evidence, ["host-1"]);
  });

  test("device with RDP (3389) port open → smb-rdp-exposure warn", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "host-1", device_type: "laptop", ports_open: [3389] }),
    ]);
    assert.ok(report.insights.find((i) => i.id === "smb-rdp-exposure"));
  });

  test("device with both 445 and 3389 still counts as 1 device", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "host-1", device_type: "laptop", ports_open: [445, 3389] }),
    ]);
    const expo = report.insights.find((i) => i.id === "smb-rdp-exposure")!;
    assert.match(expo.title, /^1 device/);
  });

  test("5+ devices with >40% unknown → unknown-coverage info", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "u-1", device_type: "unknown" }),
      makeDevice({ id: "u-2", device_type: "unknown" }),
      makeDevice({ id: "u-3", device_type: "unknown" }),
      makeDevice({ id: "k-1", device_type: "router" }),
      makeDevice({ id: "k-2", device_type: "phone" }),
    ]);
    const cov = report.insights.find((i) => i.id === "unknown-coverage");
    assert.ok(cov);
    assert.equal(cov.severity, "info");
  });

  test("under 5 devices → no unknown-coverage insight regardless of ratio", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "u-1", device_type: "unknown" }),
      makeDevice({ id: "u-2", device_type: "unknown" }),
      makeDevice({ id: "u-3", device_type: "unknown" }),
    ]);
    assert.ok(!report.insights.some((i) => i.id === "unknown-coverage"));
  });

  test("new_device flag → new-devices info", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "fresh-1", device_type: "laptop", flags: ["new_device"] }),
    ]);
    const fresh = report.insights.find((i) => i.id === "new-devices");
    assert.ok(fresh);
    assert.equal(fresh.severity, "info");
    assert.deepEqual(fresh.evidence, ["fresh-1"]);
  });

  test("byDeviceType counts every device_type", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "a", device_type: "router" }),
      makeDevice({ id: "b", device_type: "phone" }),
      makeDevice({ id: "c", device_type: "phone" }),
      makeDevice({ id: "d", device_type: "iot" }),
    ]);
    assert.deepEqual(report.byDeviceType, { router: 1, phone: 2, iot: 1 });
  });

  test("risk roll-up: critical present → high (camera + IoT)", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "cam", device_type: "camera" }),
      makeDevice({ id: "iot-1", device_type: "iot" }),
      makeDevice({ id: "iot-2", device_type: "iot" }),
      makeDevice({ id: "iot-3", device_type: "iot" }),
    ]);
    // Camera is critical → high, even though IoT density is only warn.
    assert.equal(report.riskLevel, "high");
  });

  test("risk roll-up: only warn → medium", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "host-1", device_type: "laptop", ports_open: [445] }),
    ]);
    assert.equal(report.riskLevel, "medium");
  });

  test("risk roll-up: only info → low (info is informational, doesn't lift the level)", () => {
    const report = summarizeNetwork([
      makeDevice({ id: "fresh-1", device_type: "laptop", flags: ["new_device"] }),
    ]);
    assert.equal(report.riskLevel, "low");
    assert.ok(report.insights.some((i) => i.id === "new-devices"));
  });
});
