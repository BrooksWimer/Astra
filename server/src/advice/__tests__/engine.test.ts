import { test } from "vitest";
import assert from "node:assert/strict";

import type { AdviceRequest } from "@netwise/shared";

import { getAdvice } from "../engine.js";

/**
 * Behavior contract for the rule-based /advice engine. Each test pins one
 * branch of the rules in engine.ts so a future tweak is forced to update
 * the corresponding expectation instead of silently regressing.
 *
 * The engine accepts whatever input the route validates with
 * adviceRequestSchema; these tests build minimal AdviceRequest fixtures
 * directly to exercise the rule branches in isolation.
 */

function baseRequest(
  overrides: Partial<AdviceRequest["device"]> & {
    user_context?: AdviceRequest["user_context"];
  } = {},
): AdviceRequest {
  const { user_context, ...deviceOverrides } = overrides;
  return {
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
      device_type: "phone",
      ...deviceOverrides,
    },
    network: {},
    user_context: user_context ?? "home",
  };
}

test("router device → 'Secure your router' action + risk_level >= medium", () => {
  const out = getAdvice(baseRequest({ device_type: "router" }));
  assert.equal(out.actions.length, 1);
  assert.equal(out.actions[0].title, "Secure your router");
  assert.ok(["medium", "high"].includes(out.risk_level));
  assert.ok(out.reasons.some((r) => r.includes("router")));
});

test("unknown device_type → 'Verify unknown device' action + medium risk + uncertainty note", () => {
  const out = getAdvice(baseRequest({ device_type: "unknown" }));
  assert.ok(out.actions.some((a) => a.title === "Verify unknown device"));
  assert.equal(out.risk_level, "medium");
  assert.ok(out.uncertainty_notes.length > 0);
});

test("home network with open port 445 → high risk + soon urgency", () => {
  const out = getAdvice(baseRequest({ ports_open: [445], user_context: "home" }));
  assert.equal(out.risk_level, "high");
  const portAction = out.actions.find((a) => a.title === "Review open high-risk ports");
  assert.ok(portAction, "expected the high-risk-ports action to be present");
  assert.equal(portAction.urgency, "soon");
  assert.ok(out.reasons.some((r) => r.includes("445")));
});

test("airbnb network with open port 3389 → at least medium risk + nice_to_have urgency", () => {
  const out = getAdvice(baseRequest({ ports_open: [3389], user_context: "airbnb" }));
  assert.ok(["medium", "high"].includes(out.risk_level));
  const portAction = out.actions.find((a) => a.title === "Review open high-risk ports");
  assert.ok(portAction);
  assert.equal(portAction.urgency, "nice_to_have");
});

test("new_device flag → 'Confirm new device' action", () => {
  const out = getAdvice(baseRequest({ flags: ["new_device"] }));
  assert.ok(out.actions.some((a) => a.title === "Confirm new device"));
  assert.ok(out.reasons.some((r) => r.includes("first seen")));
});

test("benign laptop with no open ports, no flags → low risk, generic summary", () => {
  const out = getAdvice(baseRequest({ device_type: "laptop" }));
  assert.equal(out.risk_level, "low");
  assert.equal(out.actions.length, 0);
  assert.match(out.summary, /No specific risks identified/);
});

test("speaker / camera device_types are not misclassified as unknown (enum-drift regression)", () => {
  // schema-level test guarantees these device_types pass validation;
  // this guarantees the engine doesn't surface the "Verify unknown
  // device" action for them — that action is reserved for device_type
  // === "unknown".
  for (const dt of ["speaker", "camera"] as const) {
    const out = getAdvice(baseRequest({ device_type: dt }));
    assert.ok(
      !out.actions.some((a) => a.title === "Verify unknown device"),
      `device_type "${dt}" should not surface the "Verify unknown device" action`,
    );
    assert.ok(
      !out.uncertainty_notes.some((n) => n.includes("could not be inferred")),
      `device_type "${dt}" should not emit an "unknown device_type" uncertainty note`,
    );
  }
});

test("camera device → high risk + 'Lock down camera defaults' + 'Segment cameras'", () => {
  const out = getAdvice(baseRequest({ device_type: "camera" }));
  assert.equal(out.risk_level, "high");
  assert.ok(out.actions.some((a) => a.title === "Lock down camera defaults"));
  assert.ok(out.actions.some((a) => a.title === "Segment cameras off the main network"));
  const lockDown = out.actions.find((a) => a.title === "Lock down camera defaults");
  assert.equal(lockDown?.urgency, "now");
  assert.ok(out.reasons.some((r) => r.toLowerCase().includes("camera")));
});

test("iot device → medium risk + 'Keep IoT devices isolated'", () => {
  const out = getAdvice(baseRequest({ device_type: "iot" }));
  assert.equal(out.risk_level, "medium");
  assert.ok(out.actions.some((a) => a.title === "Keep IoT devices isolated"));
  assert.ok(out.reasons.some((r) => r.toLowerCase().includes("iot")));
});

test("printer device → low risk + 'Keep printer firmware current' (nice_to_have)", () => {
  const out = getAdvice(baseRequest({ device_type: "printer" }));
  assert.equal(out.risk_level, "low");
  const printerAction = out.actions.find((a) => a.title === "Keep printer firmware current");
  assert.ok(printerAction);
  assert.equal(printerAction.urgency, "nice_to_have");
});

test("tv device → low risk + 'Review smart-TV privacy + updates' (nice_to_have)", () => {
  const out = getAdvice(baseRequest({ device_type: "tv" }));
  assert.equal(out.risk_level, "low");
  const tvAction = out.actions.find((a) => a.title === "Review smart-TV privacy + updates");
  assert.ok(tvAction);
  assert.equal(tvAction.urgency, "nice_to_have");
});

test("speaker device → low risk + 'Review voice-assistant privacy' (nice_to_have)", () => {
  const out = getAdvice(baseRequest({ device_type: "speaker" }));
  assert.equal(out.risk_level, "low");
  const speakerAction = out.actions.find((a) => a.title === "Review voice-assistant privacy");
  assert.ok(speakerAction);
  assert.equal(speakerAction.urgency, "nice_to_have");
});

test("risk-level escalation never reduces (camera + port 445 on home stays at high)", () => {
  // Regression for the bump() helper: a high-risk rule (camera) followed
  // by a medium-bump rule (port 445 on a non-home context) must not
  // drop the level back to medium.
  const out = getAdvice(
    baseRequest({ device_type: "camera", ports_open: [445], user_context: "airbnb" }),
  );
  assert.equal(out.risk_level, "high");
});

test("hostname undefined (omitted entirely) is accepted by the engine", () => {
  // hostname optionality drift fix: schema marks hostname as not-required,
  // so the engine has to tolerate `undefined` here. This pins that.
  const req = baseRequest();
  delete (req.device as { hostname?: unknown }).hostname;
  const out = getAdvice(req);
  assert.ok(out);
  assert.equal(out.risk_level, "low");
});
