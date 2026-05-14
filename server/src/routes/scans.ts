/**
 * Scan ingestion + retrieval routes.
 *
 * The scanner (Go agent on desktop, limited on-device probing on mobile)
 * runs locally, then POSTs the result to the server so that:
 *
 *   - Both the mobile and desktop apps for the same install can show the
 *     latest known state of the network (cross-device sync).
 *   - The server can run aggregate, network-level insights that the
 *     per-device advice engine can't (see src/scans/insight.ts).
 *
 * Identity is via the anonymous handle (see src/handles/index.ts) — no
 * accounts, no PII, just a UUID the install generates once and reuses.
 */

import { Router } from "express";
import { z } from "zod";

import { getAdvice } from "../advice/engine.js";
import { adviceRequestSchema } from "../advice/schema.js";
import { extractHandle, missingHandleError } from "../handles/index.js";
import { saveScan, getScanById, getLatestScanForHandle } from "../scans/store.js";
import { summarizeNetwork } from "../scans/insight.js";

const deviceSchema = adviceRequestSchema.shape.device;

const saveScanBodySchema = z.object({
  network: z.object({
    subnet: z.string().optional(),
    gateway_ip: z.string().optional(),
    local_ip: z.string().optional(),
    interface_name: z.string().optional(),
  }),
  devices: z.array(deviceSchema),
  scan_started_at: z.string(),
  scan_finished_at: z.string().nullable().optional(),
});

export const scansRouter = Router();

scansRouter.post("/", (req, res) => {
  const handle = extractHandle(req);
  if (!handle) {
    return res.status(400).json(missingHandleError);
  }

  const parsed = saveScanBodySchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "Invalid scan payload",
      details: parsed.error.flatten(),
    });
  }

  const stored = saveScan({
    handle,
    network: parsed.data.network,
    // Zod has narrowed each device to the canonical shape; cast away the
    // discriminated-Optional churn from the .optional() shape.
    devices: parsed.data.devices as never,
    scanStartedAt: parsed.data.scan_started_at,
    scanFinishedAt: parsed.data.scan_finished_at ?? null,
  });

  res.status(201).json({
    id: stored.id,
    handle: stored.handle,
    device_count: stored.devices.length,
    scan_started_at: stored.scanStartedAt,
    scan_finished_at: stored.scanFinishedAt,
    created_at: stored.createdAt,
  });
});

scansRouter.get("/latest", (req, res) => {
  const handle = extractHandle(req);
  if (!handle) {
    return res.status(400).json(missingHandleError);
  }
  const scan = getLatestScanForHandle(handle);
  if (!scan) {
    return res.status(404).json({ error: "No scans for handle" });
  }
  return res.json(scan);
});

scansRouter.get("/:id", (req, res) => {
  const handle = extractHandle(req);
  if (!handle) {
    return res.status(400).json(missingHandleError);
  }
  const scan = getScanById(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: "Scan not found" });
  }
  if (scan.handle !== handle) {
    // Don't leak existence of other handles' scans. Same error as not-found.
    return res.status(404).json({ error: "Scan not found" });
  }
  return res.json(scan);
});

scansRouter.post("/:id/advice", (req, res) => {
  const handle = extractHandle(req);
  if (!handle) {
    return res.status(400).json(missingHandleError);
  }
  const scan = getScanById(req.params.id);
  if (!scan || scan.handle !== handle) {
    return res.status(404).json({ error: "Scan not found" });
  }

  const userContext = (req.body as { user_context?: string } | undefined)?.user_context ?? "home";
  // Same enum the advice engine validates per-device.
  const userContextParsed = z
    .enum(["home", "airbnb", "office", "unknown"])
    .safeParse(userContext);
  if (!userContextParsed.success) {
    return res.status(400).json({ error: "Invalid user_context" });
  }

  const perDevice = scan.devices.map((device) => ({
    device_id: device.id,
    advice: getAdvice({
      scan_id: scan.id,
      device_id: device.id,
      device,
      network: scan.network,
      user_context: userContextParsed.data,
    }),
  }));

  const network = summarizeNetwork(scan.devices);

  res.json({
    scan_id: scan.id,
    handle: scan.handle,
    device_count: scan.devices.length,
    devices: perDevice,
    network,
  });
});
