#!/usr/bin/env bash
# SAN-880: differential parity gate between the Python reference
# implementation (reference/diff_harness.py) and its TypeScript port
# (reference/ts/dist/src/diff_harness.js). Runs EXACTLY FOUR byte-for-byte
# `cmp` comparisons: corpus mode over oracles.json and generated.json, and
# matrix mode over an allowlist-projected, ID-scrubbed, check-enumerated
# rebuild of each source file. Matrix mode prevents fixture-metadata /
# check-selection peeking (the harness never sees "expected", "notes",
# "base_oracle", or variant fields, and the original fixture "id" is
# discarded in favor of a synthetic, check-indexed id) and proves
# differential equivalence over the tested corpus. It does not by itself
# prove the absence of all hardcoding or establish normative correctness.
#
# Per the SAN-880/SAN-883 slice boundary, this script also asserts the
# fixture corpora are NFC before evaluation -- the harness itself does not
# normalize (normalize() is out of scope for this slice; see SAN-883).
set -euo pipefail

# Resolve the repository root from THIS SCRIPT'S OWN location, never the
# caller's cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"

WORKDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

ORACLES_PATH="$REPO_ROOT/reference/fixtures/oracles.json"
GENERATED_PATH="$REPO_ROOT/reference/fixtures/generated.json"
PY_CLI="$REPO_ROOT/reference/diff_harness.py"
TS_CLI="$REPO_ROOT/reference/ts/dist/src/diff_harness.js"

echo "== SAN-880 differential parity: Python vs TypeScript reference implementation ==" >&2

# ---------------------------------------------------------------------
# NFC invariant (SAN-883 boundary): the fixture corpora must already be
# NFC. This script asserts; it never normalizes.
# ---------------------------------------------------------------------
python3 - "$ORACLES_PATH" "$GENERATED_PATH" <<'PYEOF'
import json
import sys
import unicodedata


def walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)
    elif isinstance(value, dict):
        for v in value.values():
            yield from walk_strings(v)


for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for s in walk_strings(data):
        if unicodedata.normalize("NFC", s) != s:
            sys.stderr.write(f"NOT NFC: {path} contains a non-NFC string: {s!r}\n")
            sys.exit(1)
    sys.stderr.write(f"NFC OK: {path}\n")
PYEOF

# ---------------------------------------------------------------------
# Build the TypeScript CLI (idempotent -- this script must be runnable
# standalone, not only as the tail of the CI job that already built it).
# ---------------------------------------------------------------------
( cd "$REPO_ROOT/reference/ts" && npm run build >&2 )

if [ ! -f "$TS_CLI" ]; then
  echo "TypeScript CLI not found at $TS_CLI after build" >&2
  exit 1
fi

# ---------------------------------------------------------------------
# Letter-table drift gate (SAN-880 amendment, review round 2): fails loud
# on either drift between the committed
# reference/ts/src/unicode_letters_v15.ts and its generator, or on a
# non-15.0.0 Python (see scripts/generate_letter_table_u15.py).
# ---------------------------------------------------------------------
python3 "$REPO_ROOT/scripts/generate_letter_table_u15.py" --check

# ---------------------------------------------------------------------
# 1-2. CORPUS MODE: byte-diff Python vs TypeScript harness output over
# the two fixture files as-is.
# ---------------------------------------------------------------------
run_corpus() {
  local name="$1" path="$2"
  local py_out="$WORKDIR/py_corpus_${name}.json"
  local ts_out="$WORKDIR/ts_corpus_${name}.json"
  python3 "$PY_CLI" "$path" > "$py_out"
  node "$TS_CLI" "$path" > "$ts_out"
  if ! cmp -s "$py_out" "$ts_out"; then
    echo "CORPUS MODE MISMATCH: $name ($path)" >&2
    diff -u "$py_out" "$ts_out" | head -40 >&2
    exit 1
  fi
  echo "CORPUS MODE OK: $name" >&2
}

run_corpus oracles "$ORACLES_PATH"
run_corpus generated "$GENERATED_PATH"

# ---------------------------------------------------------------------
# 3-4. MATRIX MODE: for each source file independently, in original
# array order, project every fixture through an allowlist containing
# ONLY {output, exactly one of context/context_sources/context_repeat,
# synthetic id, check_id}. For zero-based source index i, emit exactly
# four records in C1,C2,C3,C4 order with IDs
# matrix:<oracles|generated>:<six-digit-i>:<C1|C2|C3|C4>. The original
# fixture id is discarded.
# ---------------------------------------------------------------------
build_matrix() {
  local src_name="$1" src_path="$2" out_path="$3"
  python3 - "$src_name" "$src_path" "$out_path" <<'PYEOF'
import json
import sys

src_name, src_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
ALLOWED_CONTEXT_KEYS = ("context", "context_sources", "context_repeat")
CHECK_IDS = ("C1", "C2", "C3", "C4")

with open(src_path, encoding="utf-8") as f:
    records = json.load(f)

out = []
for i, rec in enumerate(records):
    ctx_keys = [k for k in ALLOWED_CONTEXT_KEYS if k in rec]
    if len(ctx_keys) != 1:
        sys.stderr.write(f"{src_path}[{i}]: expected exactly one context shape, got {ctx_keys}\n")
        sys.exit(1)
    ctx_key = ctx_keys[0]
    if "output" not in rec:
        sys.stderr.write(f"{src_path}[{i}]: missing required 'output' field\n")
        sys.exit(1)
    for check_id in CHECK_IDS:
        out.append(
            {
                "id": f"matrix:{src_name}:{i:06d}:{check_id}",
                "check_id": check_id,
                "output": rec["output"],
                ctx_key: rec[ctx_key],
            }
        )

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(out, f)
PYEOF
}

# Assert BEFORE evaluation: every record has exactly the allowed keys and
# one context shape; synthetic IDs are well-formed, unique, and every
# source index occurs exactly once per check; the total record count is
# exactly 4x the source count.
assert_matrix_cardinality() {
  local matrix_path="$1" expected_source_count="$2" expected_total="$3"
  python3 - "$matrix_path" "$expected_source_count" "$expected_total" <<'PYEOF'
import json
import re
import sys

path, expected_source_count, expected_total = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
with open(path, encoding="utf-8") as f:
    records = json.load(f)

if len(records) != expected_total:
    sys.stderr.write(f"{path}: expected {expected_total} matrix records, got {len(records)}\n")
    sys.exit(1)

ALLOWED_KEYS = {"id", "check_id", "output", "context", "context_sources", "context_repeat"}
CONTEXT_KEYS = {"context", "context_sources", "context_repeat"}
ID_RE = re.compile(r"^matrix:[a-z]+:(\d{6}):(C[1-4])$")

seen_ids = set()
per_check_indices = {"C1": set(), "C2": set(), "C3": set(), "C4": set()}

for rec in records:
    keys = set(rec.keys())
    if not keys <= ALLOWED_KEYS:
        sys.stderr.write(f"{path}: record has disallowed keys: {keys - ALLOWED_KEYS}\n")
        sys.exit(1)
    if "id" not in keys or "check_id" not in keys or "output" not in keys:
        sys.stderr.write(f"{path}: record missing a required allowlist key: {rec}\n")
        sys.exit(1)
    ctx_keys = keys & CONTEXT_KEYS
    if len(ctx_keys) != 1:
        sys.stderr.write(f"{path}: record does not have exactly one context shape: {ctx_keys}\n")
        sys.exit(1)
    m = ID_RE.match(rec["id"])
    if not m:
        sys.stderr.write(f"{path}: malformed synthetic id {rec['id']!r}\n")
        sys.exit(1)
    if rec["id"] in seen_ids:
        sys.stderr.write(f"{path}: duplicate synthetic id {rec['id']!r}\n")
        sys.exit(1)
    seen_ids.add(rec["id"])
    idx = int(m.group(1))
    check_id = m.group(2)
    if check_id != rec["check_id"]:
        sys.stderr.write(f"{path}: id/check_id mismatch on {rec['id']!r}\n")
        sys.exit(1)
    per_check_indices[check_id].add(idx)

expected_indices = set(range(expected_source_count))
for check_id, indices in per_check_indices.items():
    if indices != expected_indices:
        sys.stderr.write(f"{path}: {check_id} does not cover every source index exactly once\n")
        sys.exit(1)

sys.stderr.write(
    f"MATRIX CARDINALITY OK: {path} ({len(records)} records, "
    f"{expected_source_count} source indices x 4 checks)\n"
)
PYEOF
}

ORACLES_SOURCE_COUNT=$(python3 -c "import json; print(len(json.load(open('$ORACLES_PATH'))))")
GENERATED_SOURCE_COUNT=$(python3 -c "import json; print(len(json.load(open('$GENERATED_PATH'))))")

if [ "$ORACLES_SOURCE_COUNT" != "56" ]; then
  echo "oracles.json count changed: expected 56, got $ORACLES_SOURCE_COUNT (Phase-3 matrix cardinality assertions must be updated)" >&2
  exit 1
fi
if [ "$GENERATED_SOURCE_COUNT" != "190" ]; then
  echo "generated.json count changed: expected 190, got $GENERATED_SOURCE_COUNT (Phase-3 matrix cardinality assertions must be updated)" >&2
  exit 1
fi

MATRIX_ORACLES="$WORKDIR/matrix_oracles.json"
MATRIX_GENERATED="$WORKDIR/matrix_generated.json"

build_matrix oracles "$ORACLES_PATH" "$MATRIX_ORACLES"
build_matrix generated "$GENERATED_PATH" "$MATRIX_GENERATED"

assert_matrix_cardinality "$MATRIX_ORACLES" 56 224
assert_matrix_cardinality "$MATRIX_GENERATED" 190 760

TOTAL_MATRIX=$((224 + 760))
if [ "$TOTAL_MATRIX" != "984" ]; then
  echo "internal error: total matrix record count arithmetic is wrong ($TOTAL_MATRIX != 984)" >&2
  exit 1
fi
echo "MATRIX CARDINALITY OK: total $TOTAL_MATRIX records (984 expected: 246 source fixtures x 4 checks)" >&2

run_matrix() {
  local name="$1" path="$2"
  local py_out="$WORKDIR/py_matrix_${name}.json"
  local ts_out="$WORKDIR/ts_matrix_${name}.json"
  python3 "$PY_CLI" "$path" > "$py_out"
  node "$TS_CLI" "$path" > "$ts_out"
  if ! cmp -s "$py_out" "$ts_out"; then
    echo "MATRIX MODE MISMATCH: $name ($path)" >&2
    diff -u "$py_out" "$ts_out" | head -40 >&2
    exit 1
  fi
  echo "MATRIX MODE OK: $name" >&2
}

run_matrix oracles "$MATRIX_ORACLES"
run_matrix generated "$MATRIX_GENERATED"

echo "ALL FOUR PARITY COMPARISONS PASSED (corpus x2, matrix x2)." >&2
