# ADR-0011: CLAUDE.md → AGENTS.md Migration; Thin Router Committed, Not Gitignored

## Status

Accepted

## Date

2026-04-26

## Context

SAN-217 and SAN-233 gitignored `CLAUDE.md` across 7 Sanna repos on the grounds that it was "per-developer Claude Code context" — appropriate for a 200+ line file mixing LLM context with architectural reference, version literals, and security hardening notes. The approach was correct for that content but created a structural problem when applied categorically.

SAN-326 surfaced that a gitignored thin router (15–20 lines of critical rules + pointers) has three governance failures:

1. **Zero audit visibility.** Auditors cannot see gitignored content. The thin router is the LLM's entry point into the repo's governance conventions. If auditors cannot see it, they cannot verify that LLM contributors are operating under the correct constraints.
2. **No fresh-clone visibility.** A contributor cloning the repo for the first time has no router file. They encounter the codebase without the "read docs/architecture.md, never skip hooks, one branch = one scope" guidance. The gitignore pattern that was protecting against committing a 200-line personal scratch file was also preventing the thin governance router from being committed.
3. **No cross-tool coverage.** `CLAUDE.md` is Claude Code–specific. Other LLM tools (Codex CLI, Copilot CLI, Gemini CLI, Cursor) do not read `CLAUDE.md`. `AGENTS.md` is the emerging cross-tool standard recognized by all of these tools. Claude Code falls back to `AGENTS.md` when `CLAUDE.md` is absent.

Anthropic's official guidance states that `CLAUDE.md` should be committed to git. The SAN-217/233 gitignore pattern directly contradicted this guidance. SAN-326 discovery (2026-04-26) confirmed the gitignored-thin-router design is governance-incorrect and the AGENTS.md cross-tool standard is the right target.

## Decision

**`AGENTS.md` is committed at each repo root as the thin-router file.** ~20 lines: critical rules (never skip hooks, never `git add -f`, never bake Notion URLs into commits, one branch = one scope) + pointers to `docs/architecture.md`, `docs/state.md`, `docs/decisions/`, and `docs/conventions.md`.

**`CLAUDE.local.md` is gitignored** for per-developer scratch content (rare; most developers have nothing that belongs there after the migration).

**`docs/architecture.md`** and **`docs/state.md`** are committed alongside, containing the architectural rationale and auto-generated state (version literals, test counts, source layout) that previously lived in the bloated `CLAUDE.md`.

**`docs/decisions/`** (this directory) captures the architectural decision rationale that previously lived only in Notion ticket Notes.

The SAN-217/SAN-233 over-correction (gitignoring CLAUDE.md across all repos) is explicitly reversed by SAN-326.

## Alternatives Considered

- **Continue with gitignored CLAUDE.md.** Rejected: (1) directly contradicts Anthropic's official guidance that CLAUDE.md should be committed; (2) no audit visibility; (3) no fresh-clone guidance; (4) Claude Code–only; (5) the original reasoning ("200-line personal scratch") does not apply to a 20-line thin router.
- **Commit CLAUDE.md only (not AGENTS.md).** Rejected: AGENTS.md adoption opens the door to non-Claude LLM tools. The cross-tool standard reduces maintenance overhead — one file read by all tools vs. per-tool config files. Claude Code falls back to AGENTS.md when CLAUDE.md is absent, so adopting AGENTS.md as primary gives Claude Code coverage while also serving other tools.
- **Gitignore both, use per-tool config files.** Rejected: each tool's separate config duplicates content and diverges over time. The cross-tool standard was designed to avoid exactly this fragmentation.
- **Leave CLAUDE.md committed as-is (large, mixed-concerns).** Rejected: the 200-line mixed-concerns CLAUDE.md caused SAN-217-class drift (version literals, test counts, file:line references rot on every protocol bump). The migration to auto-generated state and committed docs eliminates the drift class, not just this instance.

## Consequences

- SAN-326 propagation across all 7 repos: sanna, sanna-ts, sanna-protocol, sanna-openclaw, sanna-cloud, sanna-dashboard, sanna-admin.
- SAN-217/233 over-correction explicitly reversed. CLAUDE.md (or AGENTS.md) is committed, not gitignored.
- Auditors and IETF reviewers see the thin router (governance conventions + doc pointers) on first repo glance without Notion access.
- LLM tools (Claude Code, Codex CLI, Copilot CLI, Gemini CLI, Cursor) find their context on fresh clones.
- Existing gitignored local CLAUDE.md files: content migrated to docs/architecture.md (architectural rationale), docs/state.md (auto-generated literals), docs/decisions/ (ADRs), and the committed AGENTS.md router (critical rules).
- SAN-217-class drift (CLAUDE.md version literals rotting) stops recurring: auto-generated state docs replace manual literals.

## References

- SAN-326 (CLAUDE.md restructure: thin router + committed authoritative docs + auto-generated state)
- SAN-217 (CLAUDE.md refresh, drift correction — identified the drift-class this migration eliminates)
- SAN-233 (Gitignore CLAUDE.md in sanna-cloud, sanna-dashboard, sanna-admin — the over-correction this ADR explicitly reverses)
- ADR-0001 (ADR convention — docs/decisions/ bootstrap that accompanies this migration)
- Anthropic Claude Code documentation: CLAUDE.md should be committed to git
- AGENTS.md cross-tool standard (recognized by Codex CLI, Copilot CLI, Gemini CLI, Cursor, Claude Code fallback)
