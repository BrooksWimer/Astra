/**
 * Express app factory. Exported separately from `index.ts` so the same
 * `app` configuration can be used by both the production entry point
 * (which calls `.listen(PORT)`) and tests (which call `.listen(0)` to
 * grab an ephemeral port).
 */

import cors from "cors";
import express, { type Express } from "express";

import { adviceRouter } from "./routes/advice.js";

export function createApp(): Express {
  const app = express();
  app.use(cors());
  app.use(express.json());

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.use("/advice", adviceRouter);

  return app;
}
