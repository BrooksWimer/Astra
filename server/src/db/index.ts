/**
 * SQLite persistence layer for the Astra server.
 *
 * Single-process, synchronous via better-sqlite3. The server is a single
 * Node process today; the database file is the source of truth for the
 * cross-device sync flow (M3 in PROJECT_ROADMAP.md). Multi-process
 * scaling can switch to a server DB later — none of the SQL syntax here
 * is SQLite-only.
 */

import Database, { type Database as DB } from "better-sqlite3";

import { SCHEMA_SQL } from "./schema.js";

let db: DB | null = null;

export interface OpenDbOptions {
  /**
   * Path to the SQLite file. Defaults to `./data/astra.db`. Pass `:memory:`
   * for tests so each test starts with an empty database.
   */
  path?: string;
}

export function openDb(options: OpenDbOptions = {}): DB {
  const path = options.path ?? process.env.ASTRA_DB_PATH ?? "./data/astra.db";
  db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  applySchema(db);
  return db;
}

export function getDb(): DB {
  if (!db) {
    throw new Error("Database not initialized. Call openDb() first.");
  }
  return db;
}

export function closeDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function applySchema(connection: DB): void {
  // The schema lives as a TS constant in db/schema.ts so it ships inside
  // dist/ without a separate copy step. The original .sql file is kept
  // as the canonical source — db/schema.ts re-exports it as a string so
  // CREATE TABLE statements can still be reviewed in SQL syntax.
  connection.exec(SCHEMA_SQL);
}
