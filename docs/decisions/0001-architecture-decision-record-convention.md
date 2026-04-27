# ADR-0001: Architecture Decision Record Convention

## Status

Accepted

## Date

2026-04-26

## Context

Sanna had load-bearing architectural decisions captured only in Notion ticket Notes. Auditors, IETF reviewers, and future contributors look at the repo first — Notion-only decisions are invisible to them. SAN-326 surfaced the gap during the CLAUDE.md restructure: decisions on fingerprint formulas, authority matching semantics, NFC normalization scope, and enforcement derivation existed only as Notion Notes, unreachable from any repo entrypoint.

The same pattern recurred repeatedly: a protocol choice would be made, the reasoning would land in a Notion ticket, and future contributors (or future Claude Code sessions) encountering the code without Notion access had no way to know what was decided, what was rejected, or why.

Per-developer files (CLAUDE.md) were gitignored and thus invisible to auditors. Spec documents record what the protocol does, not why a specific alternative was rejected. VERSIONING.md captures migration rules, not decision rationale.

## Decision

`sanna-protocol/docs/decisions/` is the canonical home for cross-SDK protocol-level decisions. This covers decisions that affect:

- How any two SDKs must behave identically (cross-SDK contract).
- The protocol wire format or fingerprint formula.
- Universal enforcement patterns applicable to all SDK implementers.

Per-repo decisions (if and when needed) live in that repo's own `docs/decisions/` directory. The naming, section structure, and lifecycle documented in `docs/decisions/README.md` apply in all cases.

New architectural decisions get an ADR filed before or with the implementing PR, from this decision forward. Retroactive ADRs (like this set) are mined from the highest-value Notion ticket Notes.

## Alternatives Considered

- **Continue Notion-only.** Rejected: invisible to auditors, IETF reviewers, and contributors without Notion access. Notion is the verbose discussion record, not the authoritative decision record.
- **Per-repo ADRs only.** Rejected: fragments cross-SDK rationale. A decision about how Python and TypeScript must agree on authority matching belongs in the protocol, not in either SDK repo.
- **Central in sanna-repo.** Rejected: protocol decisions belong with the protocol spec. sanna-protocol is the authoritative source for the protocol contract; its `docs/decisions/` is the natural home.
- **Inline in spec document.** Rejected: the spec records what is required, not why alternatives were rejected. Mixing normative and rationale content makes the spec harder to implement against.

## Consequences

- ADRs in `docs/decisions/` are committed, versioned, and visible to anyone cloning the repo.
- Notion ticket Notes remain the verbose discussion record; ADRs are the distilled decision record.
- Auditors and IETF reviewers can find protocol rationale from the repo without Notion access.
- New architectural decisions require an ADR, adding a lightweight step to the PR process.

## References

- SAN-326 (CLAUDE.md restructure: thin router + committed authoritative docs + auto-generated state)
- ADR-0004 (first committed ADR — predates this convention, brought forward from Notion)
- `docs/decisions/README.md` (convention details: naming, sections, lifecycle, when-to-write)
