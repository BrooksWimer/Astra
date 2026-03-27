import express from "express";
import cors from "cors";
import { adviceRouter } from "./routes/advice.js";
import { assistantRouter } from "./routes/assistant.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/advice", adviceRouter);
app.use("/assistant", assistantRouter);

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`AI advice server listening on http://localhost:${PORT}`);
});
