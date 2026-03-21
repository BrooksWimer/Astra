import express from "express";
import cors from "cors";
import { adviceRouter } from "./routes/advice.js";

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/advice", adviceRouter);

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`AI advice server listening on http://localhost:${PORT}`);
});
