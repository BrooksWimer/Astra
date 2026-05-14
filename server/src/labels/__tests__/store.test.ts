import { afterEach, beforeEach, describe, test } from "vitest";
import assert from "node:assert/strict";

import { closeDb, openDb } from "../../db/index.js";
import {
  deleteLabel,
  getLabel,
  listLabelsForHandle,
  upsertLabel,
} from "../store.js";

const HANDLE_A = "55555555-5555-4555-8555-555555555555";
const HANDLE_B = "66666666-6666-4666-8666-666666666666";

describe("labels store", () => {
  beforeEach(() => {
    openDb({ path: ":memory:" });
  });

  afterEach(() => {
    closeDb();
  });

  test("upsertLabel inserts a new row and returns the hydrated label", () => {
    const stored = upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:01",
      label: "Living-room TV",
      notes: "Vizio, on guest VLAN",
      source: "mobile",
    });
    assert.equal(stored.handle, HANDLE_A);
    assert.equal(stored.deviceId, "AA:BB:CC:DD:EE:01");
    assert.equal(stored.label, "Living-room TV");
    assert.equal(stored.notes, "Vizio, on guest VLAN");
    assert.equal(stored.source, "mobile");
    assert.ok(stored.updatedAt);
  });

  test("upsertLabel updates an existing row in place (ON CONFLICT)", async () => {
    const first = upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:01",
      label: "TV",
      source: "mobile",
    });
    // datetime('now') resolves to seconds in SQLite — wait so updated_at moves.
    await new Promise((r) => setTimeout(r, 1100));
    const second = upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:01",
      label: "Living-room TV",
      notes: "Got more specific",
      source: "desktop",
    });
    assert.equal(second.label, "Living-room TV");
    assert.equal(second.notes, "Got more specific");
    assert.equal(second.source, "desktop");
    // updated_at should have advanced.
    assert.notEqual(second.updatedAt, first.updatedAt);

    // No duplicate rows from the conflict path.
    const all = listLabelsForHandle(HANDLE_A);
    assert.equal(all.length, 1);
  });

  test("getLabel returns null when missing", () => {
    assert.equal(getLabel(HANDLE_A, "AA:BB:CC:DD:EE:01"), null);
  });

  test("listLabelsForHandle returns recently-updated first", async () => {
    upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:01",
      label: "First",
      source: "mobile",
    });
    await new Promise((r) => setTimeout(r, 1100));
    upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:02",
      label: "Second",
      source: "mobile",
    });
    const list = listLabelsForHandle(HANDLE_A);
    assert.equal(list.length, 2);
    assert.equal(list[0].label, "Second"); // most-recently-updated first
    assert.equal(list[1].label, "First");
  });

  test("handles are scoped: handle B doesn't see handle A's labels", () => {
    upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:01",
      label: "TV",
      source: "mobile",
    });
    assert.equal(listLabelsForHandle(HANDLE_B).length, 0);
    assert.equal(getLabel(HANDLE_B, "AA:BB:CC:DD:EE:01"), null);
  });

  test("deleteLabel removes the row and returns true; returns false on miss", () => {
    upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:01",
      label: "TV",
      source: "mobile",
    });
    assert.equal(deleteLabel(HANDLE_A, "AA:BB:CC:DD:EE:01"), true);
    assert.equal(getLabel(HANDLE_A, "AA:BB:CC:DD:EE:01"), null);
    assert.equal(deleteLabel(HANDLE_A, "AA:BB:CC:DD:EE:01"), false);
  });

  test("label and notes can be set to null to clear them", () => {
    upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:01",
      label: "TV",
      notes: "stuff",
      source: "mobile",
    });
    upsertLabel({
      handle: HANDLE_A,
      deviceId: "AA:BB:CC:DD:EE:01",
      label: null,
      notes: null,
      source: "mobile",
    });
    const stored = getLabel(HANDLE_A, "AA:BB:CC:DD:EE:01");
    assert.ok(stored);
    assert.equal(stored.label, null);
    assert.equal(stored.notes, null);
  });
});
