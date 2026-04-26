# Sanna Protocol — AGENTS.md

AI agent context file (cross-tool standard: Claude Code, Cursor, Codex CLI,
Copilot CLI, Gemini CLI all read this). Formal specification for the Sanna
Protocol; source of truth for all SDK implementations.

## Critical rules

- Never skip hooks (`--no-verify`). On hook failure: diagnose root cause, fix, create a **new** commit — do not amend.
- Never use `git add -f`. If `.gitignore` blocks a file, stop and ask.
- Never force-push. Never push directly to main.
- Never embed notion.so URLs in any committed file (repos are public; reference tickets by ID only: SAN-NNN).
- One branch = one scope. Do not bundle unrelated work in a single branch or PR.
- Never blindly retry or suggest "refresh" — diagnose root cause.
- Trace the full call path before proposing a fix.

## Context — read these

- [docs/architecture.md](docs/architecture.md) — spec structure, fingerprint formula, cv-dispatch ladder, cross-SDK invariants
- [docs/state.md](docs/state.md) — auto-generated: spec version, checks_version, schema list, fixture count, test vector count
- [VERSIONING.md](VERSIONING.md) — normative versioning discipline for protocol + SDK coordination
- [CHANGELOG.md](CHANGELOG.md) — protocol version history
- [spec/sanna-specification-v1.4.md](spec/sanna-specification-v1.4.md) — current spec (source of truth for all SDKs)
- [schemas/receipt.schema.json](schemas/receipt.schema.json) — receipt JSON Schema (JSON Schema 2020-12)
- `docs/decisions/` — architectural decision records (ADR bootstrap forthcoming; follow-up PR per SAN-326 sequencing)

## Per-developer notes

For personal scratch (machine-specific paths, WIP rule overrides), use
`CLAUDE.local.md` (gitignored). The committed `AGENTS.md` is the canonical
shared file.
