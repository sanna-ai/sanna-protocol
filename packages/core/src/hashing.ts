/**
 * Sanna Protocol — Hashing module
 *
 * Implements canonical JSON serialization (RFC 8785 / JCS) and
 * SHA-256 hashing per the Sanna specification v1.0, Section 3.
 */

import { createHash } from "node:crypto";
// canonicalize's .d.ts uses `export default` but ships CJS — cast to fix Node16 DTS.
// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
const jcs = require("canonicalize") as (input: unknown) => string | undefined;

// ── Constants ────────────────────────────────────────────────────────

/** SHA-256 of zero bytes — the "empty" sentinel used for absent fields. */
export const EMPTY_HASH =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ── Canonicalization ─────────────────────────────────────────────────

/**
 * RFC 8785 JSON Canonicalization Scheme.
 * Returns a deterministic JSON string with sorted keys and no whitespace.
 */
export function canonicalize(obj: unknown): string {
  const result = jcs(obj);
  if (result === undefined) {
    throw new Error("canonicalize: input is not JSON-serializable");
  }
  return result;
}

// ── Hash primitives ──────────────────────────────────────────────────

/**
 * SHA-256 of raw bytes, returned as 64-char lowercase hex.
 */
export function hashBytes(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * SHA-256 of a UTF-8 string, returned as 64-char lowercase hex.
 *
 * Applies the Sanna text normalization pipeline (spec §3.3):
 *   1. NFC Unicode normalization
 *   2. Line-ending normalization (\r\n and \r → \n)
 *   3. Trailing whitespace stripped from each line
 *   4. Leading/trailing whitespace stripped from the whole string
 *   5. UTF-8 encode → SHA-256
 */
export function hashContent(data: string, truncate: number = 64): string {
  // 1. NFC normalization
  let s = data.normalize("NFC");
  // 2. Line-ending normalization
  s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  // 3. Trailing whitespace per line
  s = s
    .split("\n")
    .map((line) => line.replace(/\s+$/, ""))
    .join("\n");
  // 4. Leading/trailing strip
  s = s.trim();
  // 5. UTF-8 encode + SHA-256
  const hex = createHash("sha256").update(s, "utf-8").digest("hex");
  return hex.slice(0, truncate);
}

/**
 * Canonicalize an object then SHA-256 the canonical JSON bytes.
 * Equivalent to Python's `hash_obj()`.
 */
export function hashObj(obj: unknown): string {
  const canonical = canonicalize(obj);
  return createHash("sha256").update(canonical, "utf-8").digest("hex");
}
