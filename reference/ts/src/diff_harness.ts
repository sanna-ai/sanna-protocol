#!/usr/bin/env node
/**
 * Differential-harness CLI (SAN-880): runs a fixture file and emits
 * canonical JSON results (sorted keys, LF) to stdout. Byte-compatible with
 * reference/diff_harness.py -- this is the artifact the differential
 * parity script (scripts/check_reference_parity.sh) byte-diffs against
 * the Python harness's output.
 *
 * Usage:
 *   node dist/src/diff_harness.js <fixtures.json>
 *   node dist/src/diff_harness.js <fixtures.json> --self-check
 *
 * <fixtures.json> is a JSON array of records, each {"id": str, "check_id":
 * "C1"|"C2"|"C3"|"C4", "output": str, plus exactly one context shape:
 * "context": str, "context_sources": [{"text": str, "tier": str}], or
 * "context_repeat": {"text": str, "count": int}}. The harness reads
 * check_id for record routing, but evaluate() receives a freshly
 * constructed object containing ONLY output and its context shape -- never
 * id, check_id, expected, notes, base_oracle, or variant metadata. Only
 * "id", the context shape, "output", and "check_id" are read; every other
 * field (expected, base_oracle, notes, variant_kind, variant_field, ...)
 * is IGNORED, so this can run directly against either fixture file, or a
 * future cross-SDK corpus, or the matrix-mode projections built by
 * scripts/check_reference_parity.sh.
 *
 * PROHIBITED (spec/SAN-880 hard constraints): no fixture-ID lookup tables
 * or id-conditional behavior; no importing or subprocessing Python; no
 * runtime network access; no delegating evaluation outside this compiled
 * package (dist/).
 *
 * Output: a JSON array, one record per input fixture, each {"id", ...,
 * "check_id", "outcome", "outcome_reason", "severity", "advisory"},
 * serialized with recursively sorted keys, compact separators, and
 * ASCII-only escaping -- byte-equal to Python's json.dumps(records,
 * sort_keys=True, ensure_ascii=True, separators=(",",":")) -- terminated
 * with a single trailing newline (LF).
 *
 * --self-check: runs the TypeScript implementation over the fixture file
 * TWICE and diffs the two canonical outputs; a divergence means this
 * reference implementation is non-deterministic, which is itself a
 * defect (mirrors reference/diff_harness.py's --self-check).
 */

import { readFileSync } from "node:fs";
import { cpCompare } from "./unicode.js";
import { ContextRepeatSpec, ContextSourceRecord, Fixture, evaluate } from "./evaluate.js";

interface FixtureRecord {
  readonly id: string;
  readonly check_id: string;
  readonly output?: string;
  readonly context?: string;
  readonly context_sources?: readonly ContextSourceRecord[];
  readonly context_repeat?: ContextRepeatSpec;
  // expected / base_oracle / notes / variant_kind / variant_field / any
  // other fixture metadata: intentionally untyped and unread below.
  readonly [key: string]: unknown;
}

interface OutputRecord {
  readonly id: string;
  readonly check_id: string;
  readonly outcome: string;
  readonly outcome_reason: string;
  readonly severity: string | null;
  readonly advisory: boolean;
}

function buildFixtureInput(fx: FixtureRecord): Fixture {
  const output = typeof fx.output === "string" ? fx.output : "";
  if (fx.context_sources !== undefined) {
    return { output, context_sources: fx.context_sources };
  }
  if (fx.context_repeat !== undefined) {
    return { output, context_repeat: fx.context_repeat };
  }
  return { output, context: typeof fx.context === "string" ? fx.context : "" };
}

export function run(fixtures: readonly FixtureRecord[]): OutputRecord[] {
  const results: OutputRecord[] = [];
  for (const fx of fixtures) {
    const fixture = buildFixtureInput(fx);
    const out = evaluate(fixture);
    const got = out[fx.check_id];
    if (got === undefined) {
      throw new Error(`fixture ${JSON.stringify(fx.id)}: unknown check_id ${JSON.stringify(fx.check_id)}`);
    }
    results.push({
      id: fx.id,
      check_id: fx.check_id,
      outcome: got.outcome,
      outcome_reason: got.outcome_reason,
      severity: got.severity,
      advisory: Boolean(got.advisory),
    });
  }
  results.sort((a, b) => cpCompare(a.id, b.id));
  return results;
}

/** Escapes a string exactly as Python's json.dumps(..., ensure_ascii=True)
 * would: '\\', '"', and the seven named control escapes (\b \f \n \r \t
 * plus the implicit \\ \") get their short form; every other code point
 * < 0x20 or > 0x7e is escaped as \\uXXXX. Iterates by UTF-16 CODE UNIT
 * (not code point) deliberately -- unlike the tokenizer/extraction
 * modules, which must scan CODE POINTS for spec conformance, JSON's
 * \\uXXXX escape is itself defined over UTF-16 code units, so an astral
 * character (already stored as a surrogate pair in a JS string) is
 * escaped correctly by emitting one \\uXXXX per code unit -- exactly the
 * two-escape surrogate pair Python's C-accelerated encoder manually
 * constructs for code points >= 0x10000. */
function jsonEscapeStringAscii(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    switch (ch) {
      case "\\":
        out += "\\\\";
        continue;
      case '"':
        out += '\\"';
        continue;
      case "\b":
        out += "\\b";
        continue;
      case "\f":
        out += "\\f";
        continue;
      case "\n":
        out += "\\n";
        continue;
      case "\r":
        out += "\\r";
        continue;
      case "\t":
        out += "\\t";
        continue;
    }
    const code = s.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  out += '"';
  return out;
}

function canonicalJsonValue(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("cannot serialize a non-finite number");
    return String(v);
  }
  if (typeof v === "string") return jsonEscapeStringAscii(v);
  if (Array.isArray(v)) {
    return "[" + v.map((item) => canonicalJsonValue(item)).join(",") + "]";
  }
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort(cpCompare);
    return "{" + keys.map((k) => jsonEscapeStringAscii(k) + ":" + canonicalJsonValue(obj[k])).join(",") + "}";
  }
  throw new Error(`cannot serialize value of type ${typeof v}`);
}

/** Recursively key-sorted objects, compact separators, ASCII-only
 * escaping, one trailing newline -- byte-equal to Python's
 * json.dumps(records, sort_keys=True, ensure_ascii=True,
 * separators=(",",":")) + "\n". */
export function canonicalJson(records: unknown): string {
  return canonicalJsonValue(records) + "\n";
}

function main(argv: readonly string[]): number {
  let selfCheck = false;
  const positional: string[] = [];
  for (const arg of argv) {
    if (arg === "--self-check") selfCheck = true;
    else positional.push(arg);
  }
  if (positional.length !== 1) {
    process.stderr.write("usage: diff_harness.js <fixtures.json> [--self-check]\n");
    return 2;
  }
  const fixturesPath = positional[0]!;
  const fixtures = JSON.parse(readFileSync(fixturesPath, "utf-8")) as FixtureRecord[];

  const run1 = canonicalJson(run(fixtures));

  if (selfCheck) {
    const run2 = canonicalJson(run(fixtures));
    if (run1 !== run2) {
      process.stderr.write("SELF-CHECK FAILED: two runs of the TypeScript reference implementation diverged\n");
      return 1;
    }
    process.stderr.write(`SELF-CHECK OK: ${fixtures.length} fixtures, byte-identical across two runs\n`);
    return 0;
  }

  process.stdout.write(run1);
  return 0;
}

// Only run the CLI when this module is the process entry point (so tests
// can import `run` / `canonicalJson` without triggering argv parsing /
// stdio writes).
const isMainModule = process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  process.exitCode = main(process.argv.slice(2));
}
