"""SAN-498: regression guard that generate_state_doc.py uses git ls-files.

Three assertion tests verify generator output matches git ls-files output
(catches future Path.glob regressions). One active-verification test
creates an untracked sentinel file in fixtures/ and asserts count_fixtures
returns the baseline (37, not 38) -- this test FAILS under Path.glob and
PASSES under git ls-files, actively proving the bug is fixed.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from generate_state_doc import (
    count_fixtures,
    generate_full,
    get_schemas,
    get_spec_version,
    repo_root,
)


def _git_ls_files(root: Path, pathspec: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", pathspec],
        capture_output=True, text=True, cwd=root, check=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def test_count_fixtures_matches_git_ls_files():
    """count_fixtures must match the git index (regression guard)."""
    root = repo_root()
    expected = len(_git_ls_files(root, "fixtures/"))
    actual = count_fixtures(root)
    assert actual == expected, (
        f"count_fixtures returned {actual}; git ls-files fixtures/ returns "
        f"{expected}. Path.glob may still be in use somewhere."
    )


def test_get_schemas_matches_git_ls_files():
    """get_schemas must match the git index for schemas/*.json (regression guard)."""
    root = repo_root()
    expected = sorted(Path(p).name for p in _git_ls_files(root, "schemas/*.json"))
    actual = get_schemas(root)
    assert actual == expected, (
        f"get_schemas returned {actual}; git ls-files schemas/*.json returns "
        f"{expected}."
    )


def test_get_spec_version_uses_git_ls_files():
    """get_spec_version must derive from git index (regression guard)."""
    root = repo_root()
    expected_files = sorted(
        _git_ls_files(root, "spec/sanna-specification-v*.md"),
        reverse=True,
    )
    if not expected_files:
        # No spec files; both sides should agree on "(not found)".
        version, filename = get_spec_version(root)
        assert version == "(not found)"
        assert filename == "(not found)"
        return
    _, actual_filename = get_spec_version(root)
    assert actual_filename == expected_files[0], (
        f"get_spec_version returned filename {actual_filename}; git ls-files "
        f"latest is {expected_files[0]}."
    )


def test_count_fixtures_excludes_untracked_pollution():
    """ACTIVE verification: untracked file in fixtures/ does NOT inflate count_fixtures.

    With Path.glob (the bug), an untracked sentinel in fixtures/ inflates
    count by 1 (38 != baseline 37 -> AssertionError). With git ls-files
    (the fix), git index is unaffected by working-tree pollution (37 ==
    baseline 37 -> assert passes). This test actively proves the bug is
    fixed, beyond what regression guards catch.

    Uses tempfile.NamedTemporaryFile(dir=fixtures_dir, delete=True) so
    the sentinel auto-deletes on context exit -- same robustness as
    try/finally, cleaner API.
    """
    root = repo_root()
    fixtures_dir = root / "fixtures"
    baseline = count_fixtures(root)
    with tempfile.NamedTemporaryFile(
        dir=fixtures_dir,
        prefix="san498-untracked-sentinel-",
        suffix=".tmp",
        delete=True,
    ):
        polluted = count_fixtures(root)
    assert polluted == baseline, (
        f"count_fixtures returned {polluted} with untracked file present; "
        f"baseline (without untracked) was {baseline}. Indicates Path.glob "
        f"regression -- generator is not using git ls-files."
    )


def test_state_md_header_does_not_contain_git_sha():
    """SAN-493: state.md header must NOT embed git SHA.

    Pre-fix, the header included `git-sha: <12-char>` which was always
    one-commit-stale (regen runs pre-commit per the sealed-gate
    pattern; HEAD at that moment is the parent commit's SHA, never
    the SHA of the commit landing the state.md update). Post-fix,
    the SHA is dropped entirely; commit SHAs live only in git log.
    """
    content = generate_full(repo_root(), "2026-05-10T00:00:00Z")
    header = "\n".join(content.splitlines()[:5])
    assert "git-sha" not in header, (
        f"state.md header still contains 'git-sha' substring; "
        f"SAN-493 dropped this. Header:\n{header}"
    )
