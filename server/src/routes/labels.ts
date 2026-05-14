/**
 * Per-handle device-label sync routes.
 *
 * Pairs with src/labels/store.ts and the `device_labels` table from
 * src/db/schema.sql. Identity is the install's anonymous handle (same
 * UUIDv4 the scan routes use). Labels are scoped per-handle so a
 * mobile + desktop pair that shares a handle sees the same names.
 *
 *   PUT    /labels                                — upsert one label
 *   GET    /labels                                — list all for the handle
 *   GET    /labels/:deviceId                      — fetch one
 *   DELETE /labels/:deviceId                      — clear one
 */

import { Router } from "express";
import { z } from "zod";

import { extractHandle, missingHandleError } from "../handles/index.js";
import {
  deleteLabel,
  getLabel,
  listLabelsForHandle,
  upsertLabel,
} from "../labels/store.js";

const upsertSchema = z.object({
  device_id: z.string().min(1),
  // A user can set a label to null/empty to clear the nickname without
  // dropping the row (their notes may still be there). Same for notes.
  label: z.string().max(120).nullable().optional(),
  notes: z.string().max(2000).nullable().optional(),
  source: z.enum(["mobile", "desktop", "auto"]).default("mobile"),
});

export const labelsRouter = Router();

labelsRouter.put("/", (req, res) => {
  const handle = extractHandle(req);
  if (!handle) return res.status(400).json(missingHandleError);

  const parsed = upsertSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "Invalid label payload",
      details: parsed.error.flatten(),
    });
  }

  const stored = upsertLabel({
    handle,
    deviceId: parsed.data.device_id,
    label: parsed.data.label ?? null,
    notes: parsed.data.notes ?? null,
    source: parsed.data.source,
  });

  res.status(200).json(stored);
});

labelsRouter.get("/", (req, res) => {
  const handle = extractHandle(req);
  if (!handle) return res.status(400).json(missingHandleError);
  const labels = listLabelsForHandle(handle);
  res.json({ handle, count: labels.length, labels });
});

labelsRouter.get("/:deviceId", (req, res) => {
  const handle = extractHandle(req);
  if (!handle) return res.status(400).json(missingHandleError);
  const stored = getLabel(handle, req.params.deviceId);
  if (!stored) return res.status(404).json({ error: "Label not found" });
  res.json(stored);
});

labelsRouter.delete("/:deviceId", (req, res) => {
  const handle = extractHandle(req);
  if (!handle) return res.status(400).json(missingHandleError);
  const removed = deleteLabel(handle, req.params.deviceId);
  if (!removed) return res.status(404).json({ error: "Label not found" });
  res.status(204).end();
});
