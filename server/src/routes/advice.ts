import { Router } from "express";
import { getAdvice } from "../advice/engine.js";
import { adviceRequestSchema } from "../advice/schema.js";

export const adviceRouter = Router();

adviceRouter.post("/", (req, res) => {
  const parsed = adviceRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
  }
  const response = getAdvice(parsed.data);
  res.json(response);
});
