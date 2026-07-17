#!/usr/bin/env python3
"""SAN-880: fail-closed ASCII-only conformance checker for the TypeScript
reference-implementation port and its supporting scripts/tests.

Scans reference/ (excluding reference/ts/node_modules and reference/ts/dist),
reference/ts/src, reference/ts/test, tests/reference/, and scripts/ for
files with extension in {.py, .ts, .json, .md, .sh} and fails on ANY
non-ASCII byte.

This is a CATEGORICAL byte-range scan (byte > 0x7F), not an enumerated
Unicode-category allowlist (arrows, em-dashes, smart quotes, ...) --
per the project's ASCII-conformance memory rule, enumerating specific
Unicode classes has previously missed real violations (e.g. inequality
signs U+2260). A categorical scan cannot miss a class by omission.

Resolves the repository root from its OWN location (via __file__), never
the caller's cwd.

Usage:
    python3 scripts/check_reference_ascii.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SCAN_ROOTS = [
    REPO_ROOT / "reference",
    REPO_ROOT / "tests" / "reference",
    REPO_ROOT / "scripts",
]

EXCLUDE_DIRS = [
    REPO_ROOT / "reference" / "ts" / "node_modules",
    REPO_ROOT / "reference" / "ts" / "dist",
]

EXTENSIONS = {".py", ".ts", ".json", ".md", ".sh"}


def is_excluded(path: Path) -> bool:
    for excluded in EXCLUDE_DIRS:
        try:
            path.relative_to(excluded)
            return True
        except ValueError:
            continue
    return False


def iter_files() -> list[Path]:
    found: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in EXTENSIONS:
                continue
            if is_excluded(path):
                continue
            found.append(path)
    return sorted(found)


def find_violations(path: Path) -> list[tuple[int, int, int]]:
    """Returns [(line, col, byte_value), ...] for every non-ASCII byte in
    `path` (1-based line/col over the RAW BYTES, so this is meaningful even
    for a file that fails to UTF-8-decode)."""
    raw = path.read_bytes()
    violations = []
    line = 1
    col = 1
    for b in raw:
        if b > 0x7F:
            violations.append((line, col, b))
        if b == 0x0A:  # \n
            line += 1
            col = 1
        else:
            col += 1
    return violations


def main() -> int:
    files = iter_files()
    all_violations: list[tuple[Path, int, int, int]] = []
    for path in files:
        for line, col, b in find_violations(path):
            all_violations.append((path, line, col, b))

    if all_violations:
        sys.stderr.write("ASCII conformance check FAILED -- non-ASCII byte(s) found:\n")
        for path, line, col, b in all_violations:
            rel = path.relative_to(REPO_ROOT)
            sys.stderr.write(f"  {rel}:{line}:{col}: byte 0x{b:02x}\n")
        sys.stderr.write(f"\n{len(all_violations)} violation(s) across {len(files)} scanned file(s).\n")
        return 1

    print(f"ASCII conformance OK: {len(files)} files scanned, 0 non-ASCII bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
