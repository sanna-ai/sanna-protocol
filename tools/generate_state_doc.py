#!/usr/bin/env python3
"""
Generate docs/state.md for sanna-protocol.

Reads sources of truth and writes a deterministic state document.
Never hand-edit docs/state.md — regenerate with this script.

Usage:
    python3 tools/generate_state_doc.py          # regenerate docs/state.md
    python3 tools/generate_state_doc.py --check  # exit 1 if docs/state.md is stale
"""

import argparse
import datetime
import difflib
import json
import re
import subprocess
import sys
from pathlib import Path
from datetime import timezone


def repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(result.stdout.strip())


def git_sha(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=root,
    )
    return result.stdout.strip()[:12] if result.returncode == 0 else "unknown"


def get_spec_version(root: Path) -> tuple[str, str]:
    """Return (spec_version, spec_filename). Reads the most recent spec file."""
    spec_dir = root / "spec"
    if not spec_dir.exists():
        return ("(not found)", "(not found)")
    candidates = sorted(spec_dir.glob("sanna-specification-v*.md"), reverse=True)
    if not candidates:
        return ("(not found)", "(not found)")
    spec_file = candidates[0]
    # Extract version from filename: sanna-specification-v1.4.md → 1.4
    m = re.search(r"sanna-specification-v([0-9]+\.[0-9]+)\.md", spec_file.name)
    version = m.group(1) if m else "(unknown)"
    return (version, f"spec/{spec_file.name}")


def get_checks_version(root: Path) -> str:
    """Extract current checks_version from receipt.schema.json or spec."""
    schema_path = root / "schemas" / "receipt.schema.json"
    if schema_path.exists():
        text = schema_path.read_text()
        # Look for the current checks_version default or enum
        m = re.search(r'"checks_version"[^}]*"default"\s*:\s*"([0-9]+)"', text)
        if m:
            return m.group(1)
    # Fall back to spec file
    _, spec_filename = get_spec_version(root)
    spec_path = root / spec_filename
    if spec_path.exists():
        text = spec_path.read_text()
        m = re.search(r'The current value of `checks_version` is `"([0-9]+)"`', text)
        if m:
            return m.group(1)
    return "(unknown)"


def get_schemas(root: Path) -> list[str]:
    schemas_dir = root / "schemas"
    if not schemas_dir.exists():
        return ["(schemas/ not found)"]
    return sorted(p.name for p in schemas_dir.glob("*.json"))


def count_fixtures(root: Path) -> int:
    fixtures_dir = root / "fixtures"
    if not fixtures_dir.exists():
        return 0
    return len(list(fixtures_dir.rglob("*"))) - len(list(fixtures_dir.rglob("*/")))


def get_vector_counts(root: Path) -> dict[str, int]:
    fixtures_dir = root / "fixtures"
    counts: dict[str, int] = {}
    for vector_file in ["canonicalization-vectors.json", "authority-matching-vectors.json"]:
        p = fixtures_dir / vector_file
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
            if isinstance(data, list):
                counts[vector_file] = len(data)
            elif isinstance(data, dict):
                if "vectors" in data:
                    counts[vector_file] = len(data["vectors"])
                elif "total_vectors" in data:
                    counts[vector_file] = data["total_vectors"]
                else:
                    counts[vector_file] = 0
        except Exception:
            counts[vector_file] = -1
    return counts


def get_latest_changelog(root: Path) -> str:
    changelog = root / "CHANGELOG.md"
    if not changelog.exists():
        return "(no CHANGELOG.md)"
    entry, in_entry = [], False
    for line in changelog.read_text().splitlines():
        if line.startswith("## "):
            if in_entry:
                break
            in_entry = True
        if in_entry:
            entry.append(line)
        if len(entry) >= 10:
            break
    return "\n".join(entry) if entry else "(no entries found)"


def generate_body(root: Path) -> str:
    spec_version, spec_filename = get_spec_version(root)
    checks_version = get_checks_version(root)
    schemas = get_schemas(root)
    fixture_count = count_fixtures(root)
    vector_counts = get_vector_counts(root)
    changelog = get_latest_changelog(root)

    canon_count = vector_counts.get("canonicalization-vectors.json", 0)
    auth_count = vector_counts.get("authority-matching-vectors.json", 0)

    sections = [
        "# Sanna Protocol — State",
        "",
        "## Version",
        "",
        f"Spec version: **{spec_version}** (`{spec_filename}`)",
        f"checks_version: **\"{checks_version}\"** (current default)",
        "",
        "## Schemas",
        "",
        f"Directory: `schemas/` ({len(schemas)} files)",
        "",
        "```",
        *[f"  {s}" for s in schemas],
        "```",
        "",
        "## Fixtures",
        "",
        f"Total fixture files: {fixture_count} (`fixtures/` subtree, all types)",
        "",
        "Test vector files:",
        f"- `fixtures/canonicalization-vectors.json`: {canon_count} vectors",
        f"- `fixtures/authority-matching-vectors.json`: {auth_count} vectors",
        "",
        "## Latest CHANGELOG Entry",
        "",
        changelog,
        "",
    ]
    return "\n".join(sections)


def generate_full(root: Path, sha: str, timestamp: str) -> str:
    header = (
        f"<!-- auto-generated by tools/generate_state_doc.py — do not edit manually -->\n"
        f"<!-- generated: {timestamp}  git-sha: {sha} -->\n"
        f"\n"
    )
    return header + generate_body(root)


def _comparable(content: str) -> str:
    """Strip the volatile timestamp line before comparing."""
    lines = [l for l in content.splitlines() if not l.startswith("<!-- generated:")]
    return "\n".join(lines).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate or validate docs/state.md")
    parser.add_argument(
        "--check", action="store_true",
        help="Exit 1 if docs/state.md would change on regeneration",
    )
    args = parser.parse_args()

    root = repo_root()
    state_path = root / "docs" / "state.md"

    if args.check:
        if not state_path.exists():
            print("ERROR: docs/state.md does not exist.")
            print("Run: python3 tools/generate_state_doc.py")
            sys.exit(1)

        current = state_path.read_text()
        sha = git_sha(root)
        timestamp = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        fresh = generate_full(root, sha, timestamp)

        if _comparable(current) == _comparable(fresh):
            print("docs/state.md is up to date.")
            sys.exit(0)

        diff = list(difflib.unified_diff(
            _comparable(current).splitlines(keepends=True),
            _comparable(fresh).splitlines(keepends=True),
            fromfile="docs/state.md (committed)",
            tofile="docs/state.md (would regenerate)",
            n=3,
        ))
        print("ERROR: docs/state.md is stale. Regenerate with:")
        print("  python3 tools/generate_state_doc.py\n")
        sys.stdout.writelines(diff[:60])
        sys.exit(1)
    else:
        sha = git_sha(root)
        timestamp = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        content = generate_full(root, sha, timestamp)
        (root / "docs").mkdir(exist_ok=True)
        state_path.write_text(content)
        spec_version, _ = get_spec_version(root)
        checks_version = get_checks_version(root)
        fixture_count = count_fixtures(root)
        print(
            f"Generated docs/state.md "
            f"(sha={sha}, spec={spec_version}, cv={checks_version}, "
            f"fixtures={fixture_count})"
        )


if __name__ == "__main__":
    main()
