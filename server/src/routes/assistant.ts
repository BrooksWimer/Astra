import { Router } from "express";
import {
  getAssistantReply,
  syncAssistantContext,
} from "../assistant/engine.js";
import {
  assistantContextSyncRequestSchema,
  assistantRequestSchema,
} from "../assistant/schema.js";

export const assistantRouter = Router();

assistantRouter.post("/context", (req, res) => {
  const parsed = assistantContextSyncRequestSchema.safeParse(req.body);

  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid context sync request", details: parsed.error.flatten() });
  }

  try {
    const response = syncAssistantContext(parsed.data);
    return res.json(response);
  } catch (error) {
    console.error("[assistant] context sync failed", error);
    return res.status(500).json({ error: "Assistant context sync failed" });
  }
});

assistantRouter.post("/", async (req, res) => {
  const parsed = assistantRequestSchema.safeParse(req.body);

  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid request", details: parsed.error.flatten() });
  }

  try {
    const response = await getAssistantReply(parsed.data);
    return res.json(response);
  } catch (error) {
    console.error("[assistant] request failed", error);
    return res.status(500).json({ error: "Assistant request failed" });
  }
});
