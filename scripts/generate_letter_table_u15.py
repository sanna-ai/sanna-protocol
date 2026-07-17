#!/usr/bin/env python3
"""SAN-880 amendment (review round 2): generates
reference/ts/src/unicode_letters_v15.ts, a table of maximal contiguous
code-point ranges where chr(cp).isalpha() is True under CPython 3.12 /
Unicode Character Database (UCD) version 15.0.0.

This table pins reference/ts/src/unicode.ts's isAlphaCp() letter
classification to a fixed baseline instead of floating with the host
Node runtime's built-in \\p{L} Unicode tables, which vary release to
release (Node 22 ships Unicode 15.1; later Node releases ship later
versions still).

NORMATIVE STATUS: spec section 2.1 pins Unicode 15.0.0 for the
NORMALIZER only. Spec section 2.2 rule 4 says just "letters" with no
version pin for classification -- the letter-classification pin is
tracked separately as SAN-896. This generator/table pins TypeScript to
the CPython 3.12 / UCD 15.0.0 reference/CI baseline; it does not itself
constitute a spec-level pin.

Usage:
    python3 scripts/generate_letter_table_u15.py            # regenerate
    python3 scripts/generate_letter_table_u15.py --check     # drift check

Resolves the repository root from its OWN location (via __file__), never
the caller's cwd.
"""

from __future__ import annotations

import sys
import tempfile
import unicodedata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "reference" / "ts" / "src" / "unicode_letters_v15.ts"
GENERATOR_REL_PATH = "scripts/generate_letter_table_u15.py"

REQUIRED_UNIDATA_VERSION = "15.0.0"

SURROGATE_LO = 0xD800
SURROGATE_HI = 0xDFFF
MAX_CODEPOINT = 0x10FFFF

EXPECTED_RANGE_COUNT = 659
EXPECTED_TOTAL_CODEPOINTS = 136104
EXPECTED_FIRST_RANGE = (0x41, 0x5A)
EXPECTED_LAST_RANGE = (0x31350, 0x323AF)


def check_unidata_version() -> None:
    if unicodedata.unidata_version != REQUIRED_UNIDATA_VERSION:
        sys.stderr.write(
            "generate_letter_table_u15.py requires CPython's unicodedata "
            f"module to report UCD version {REQUIRED_UNIDATA_VERSION} "
            f"(the CPython 3.12 reference/CI baseline); got "
            f"{unicodedata.unidata_version}. Run this generator under "
            "CPython 3.12.\n"
        )
        sys.exit(1)


def is_letter(cp: int) -> bool:
    """chr(cp).isalpha() IS the provenance for this table: the generated
    ranges are defined as exactly the code points where this predicate is
    True under CPython 3.12 / UCD 15.0.0. Surrogate code points
    (U+D800-U+DFFF), which CPython can represent as lone-surrogate
    strings but which are never valid Unicode scalar values, are forced
    to False explicitly rather than relying on chr()/isalpha() behavior
    over them."""
    if SURROGATE_LO <= cp <= SURROGATE_HI:
        return False
    return chr(cp).isalpha()


def compute_ranges() -> list[tuple[int, int]]:
    """Maximal contiguous ranges of code points in [0, 0x10FFFF] where
    is_letter() is True."""
    ranges: list[tuple[int, int]] = []
    start: int | None = None
    for cp in range(0, MAX_CODEPOINT + 1):
        letter = is_letter(cp)
        if letter and start is None:
            start = cp
        elif not letter and start is not None:
            ranges.append((start, cp - 1))
            start = None
    if start is not None:
        ranges.append((start, MAX_CODEPOINT))
    return ranges


def verify_invariants(ranges: list[tuple[int, int]]) -> None:
    """Asserts the exact invariants pinned by this ticket, all
    independently re-verified by
    reference/ts/test/unicode_letters.test.ts."""
    if len(ranges) != EXPECTED_RANGE_COUNT:
        sys.stderr.write(
            f"invariant failed: expected {EXPECTED_RANGE_COUNT} ranges, "
            f"got {len(ranges)}\n"
        )
        sys.exit(1)

    total = sum(hi - lo + 1 for lo, hi in ranges)
    if total != EXPECTED_TOTAL_CODEPOINTS:
        sys.stderr.write(
            f"invariant failed: expected {EXPECTED_TOTAL_CODEPOINTS} total "
            f"letter code points, got {total}\n"
        )
        sys.exit(1)

    if ranges[0] != EXPECTED_FIRST_RANGE:
        sys.stderr.write(
            f"invariant failed: expected first range {EXPECTED_FIRST_RANGE}, "
            f"got {ranges[0]}\n"
        )
        sys.exit(1)

    if ranges[-1] != EXPECTED_LAST_RANGE:
        sys.stderr.write(
            f"invariant failed: expected last range {EXPECTED_LAST_RANGE}, "
            f"got {ranges[-1]}\n"
        )
        sys.exit(1)

    for lo, hi in ranges:
        if lo > hi:
            sys.stderr.write(f"invariant failed: malformed range ({lo}, {hi})\n")
            sys.exit(1)
        if lo < 0 or hi > MAX_CODEPOINT:
            sys.stderr.write(
                f"invariant failed: range (0x{lo:x}, 0x{hi:x}) out of "
                f"[0, 0x{MAX_CODEPOINT:x}]\n"
            )
            sys.exit(1)
        if lo <= SURROGATE_HI and hi >= SURROGATE_LO:
            sys.stderr.write(
                f"invariant failed: range (0x{lo:x}, 0x{hi:x}) intersects "
                f"the surrogate block [0x{SURROGATE_LO:x}, 0x{SURROGATE_HI:x}]\n"
            )
            sys.exit(1)

    for (_, prev_hi), (next_lo, _) in zip(ranges, ranges[1:]):
        if next_lo <= prev_hi:
            sys.stderr.write(
                "invariant failed: ranges not strictly ascending/"
                f"non-overlapping at boundary 0x{prev_hi:x} -> 0x{next_lo:x}\n"
            )
            sys.exit(1)


def render(ranges: list[tuple[int, int]]) -> str:
    lines: list[str] = []
    lines.append("// DO NOT EDIT -- generated by scripts/generate_letter_table_u15.py.")
    lines.append("//")
    lines.append("// Provenance: for every code point cp in [0, 0x10FFFF], this table")
    lines.append("// includes cp if and only if chr(cp).isalpha() is True under CPython")
    lines.append("// 3.12 / Unicode Character Database (UCD) version 15.0.0 -- that")
    lines.append("// predicate call IS the provenance, not a description of one. Lone")
    lines.append("// surrogate code points (U+D800-U+DFFF) are forced to False.")
    lines.append("//")
    lines.append("// Regenerate with:")
    lines.append("//   python3 scripts/generate_letter_table_u15.py")
    lines.append("// Verify (drift check, no write):")
    lines.append("//   python3 scripts/generate_letter_table_u15.py --check")
    lines.append("//")
    lines.append("// Invariants asserted by the generator before writing (all")
    lines.append("// independently re-verified by")
    lines.append("// reference/ts/test/unicode_letters.test.ts):")
    lines.append(f"//   - exactly {EXPECTED_RANGE_COUNT} ranges")
    lines.append(f"//   - exactly {EXPECTED_TOTAL_CODEPOINTS} total letter code points")
    lines.append(
        f"//   - first range == (0x{EXPECTED_FIRST_RANGE[0]:x}, "
        f"0x{EXPECTED_FIRST_RANGE[1]:x})"
    )
    lines.append(
        f"//   - last range == (0x{EXPECTED_LAST_RANGE[0]:x}, "
        f"0x{EXPECTED_LAST_RANGE[1]:x})"
    )
    lines.append("//   - ranges strictly ascending and non-overlapping")
    lines.append("//   - all bounds within [0, 0x10ffff]")
    lines.append("//   - no range intersects [0xd800, 0xdfff] (the surrogate block)")
    lines.append("//")
    lines.append("// NORMATIVE STATUS: spec section 2.1 pins Unicode 15.0.0 for the")
    lines.append('// NORMALIZER only; spec section 2.2 rule 4 says just "letters" with no')
    lines.append("// version pin for classification. This table pins TypeScript letter")
    lines.append("// classification to the CPython 3.12 / UCD 15.0.0 reference/CI")
    lines.append("// baseline -- it does NOT itself constitute a spec-level pin. The")
    lines.append("// spec-level pin is tracked separately as SAN-896.")
    lines.append("")
    lines.append("export const LETTER_RANGES_V15: readonly (readonly [number, number])[] = [")
    for lo, hi in ranges:
        lines.append(f"  [0x{lo:x}, 0x{hi:x}],")
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def generate_content() -> str:
    check_unidata_version()
    ranges = compute_ranges()
    verify_invariants(ranges)
    return render(ranges)


def main(argv: list[str]) -> int:
    check_mode = "--check" in argv
    content = generate_content()
    candidate_bytes = content.encode("ascii")

    if check_mode:
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".ts", delete=False
            ) as tmp:
                tmp.write(candidate_bytes)
                tmp_path = Path(tmp.name)

            if not OUTPUT_PATH.exists():
                sys.stderr.write(f"DRIFT: {OUTPUT_PATH} does not exist\n")
                return 1
            existing_bytes = OUTPUT_PATH.read_bytes()
            regenerated_bytes = tmp_path.read_bytes()
            if existing_bytes != regenerated_bytes:
                sys.stderr.write(
                    f"DRIFT: {OUTPUT_PATH} does not match the output of "
                    f"{GENERATOR_REL_PATH}; rerun without --check to "
                    "regenerate.\n"
                )
                return 1
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
        print(
            f"OK: {OUTPUT_PATH} matches generator output "
            f"({EXPECTED_RANGE_COUNT} ranges, "
            f"{EXPECTED_TOTAL_CODEPOINTS} code points)."
        )
        return 0

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="ascii", newline="\n") as f:
        f.write(content)
    print(
        f"WROTE: {OUTPUT_PATH} ({EXPECTED_RANGE_COUNT} ranges, "
        f"{EXPECTED_TOTAL_CODEPOINTS} code points)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
