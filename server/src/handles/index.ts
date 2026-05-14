/**
 * Anonymous-handle identity. The mobile and desktop clients each generate
 * a UUID v4 once at install time and pass it in either:
 *
 *   - the `X-Astra-Handle` request header (preferred), or
 *   - the `handle` query parameter (fallback for GET-from-link UX).
 *
 * No account creation. No password. No PII. A handle is a stable opaque
 * identifier the server uses to scope scans + labels per install. Two
 * devices (e.g. mobile + desktop) that share a handle are treated as
 * the same user.
 */

import type { Request } from "express";

/**
 * UUID v4 with the canonical 8-4-4-4-12 hex layout. The version nibble
 * must be `4` and the variant nibble must be in [8, 9, a, b]. We accept
 * the standard format and reject anything else so a typo doesn't end up
 * sharing scope with another install.
 */
const HANDLE_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidHandle(value: unknown): value is string {
  return typeof value === "string" && HANDLE_REGEX.test(value);
}

/**
 * Pull the handle from the request. Returns `null` if missing or invalid —
 * the route is expected to surface a 400 with a clear error envelope.
 */
export function extractHandle(req: Request): string | null {
  const header = req.header("X-Astra-Handle");
  if (isValidHandle(header)) return header.toLowerCase();
  const query = req.query.handle;
  if (typeof query === "string" && isValidHandle(query)) return query.toLowerCase();
  return null;
}

/**
 * Produce the JSON 400 error envelope for the missing-handle case. Kept in
 * one place so all routes return the same shape.
 */
export const missingHandleError = {
  error: "Missing or invalid handle",
  details:
    "Pass a UUIDv4 install handle as the `X-Astra-Handle` request header or the " +
    "`?handle=` query parameter. Generate one with crypto.randomUUID() once per install " +
    "and reuse it for every request — Astra uses it as your sync identity.",
} as const;
