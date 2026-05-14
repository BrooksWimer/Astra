import { createApp } from "./app.js";
import { openDb } from "./db/index.js";

openDb();

const app = createApp();

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`Astra server listening on http://localhost:${PORT}`);
});
