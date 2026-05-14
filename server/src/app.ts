/**
 * Express app factory. Exported separately from `index.ts` so the same
 * `app` configuration can be used by both the production entry point
 * (which calls `.listen(PORT)`) and tests (which call `.listen(0)` to
 * grab an ephemeral port).
 */

import cors from "cors";
import express, { type Express } from "express";

import { adviceRouter } from "./routes/advice.js";
import { scansRouter } from "./routes/scans.js";

export function createApp(): Express {
  const app = express();
  app.use(cors({ exposedHeaders: ["X-Astra-Handle"] }));
  // 4MB cap: a full scan with ~500 devices + protocols + ports lands around
  // 1MB; 4MB gives generous headroom without inviting denial-of-service via
  // a single huge POST.
  app.use(express.json({ limit: "4mb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.use("/advice", adviceRouter);
  app.use("/scans", scansRouter);

  return app;
}
