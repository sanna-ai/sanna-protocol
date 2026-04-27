# Architecture Decision Records

Cross-SDK protocol-level decisions for the Sanna receipt protocol.

## Home

`sanna-protocol/docs/decisions/` is the canonical home for decisions that affect cross-SDK behavior, the protocol contract, or universal patterns across the Sanna ecosystem. Per-repo decisions (if any) live in that repo's own `docs/decisions/` directory.

## File naming

```
NNNN-kebab-case-title.md
```

Zero-padded 4-digit number. Numbers are assigned in the order decisions are recorded, not in the order they were made. The Date field is authoritative for when the decision occurred.

## Fixed sections

Every ADR must have these sections in this order:

| Section | Content |
|---|---|
| **Status** | `Accepted` \| `Superseded by ADR-NNNN` \| `Proposed` |
| **Date** | ISO-8601 date the decision was made (not the date the ADR was written) |
| **Context** | What problem we are solving and why it matters |
| **Decision** | What we chose (1–2 paragraphs, normative) |
| **Alternatives considered** | What was rejected and why (bullet list) |
| **Consequences** | Known tradeoffs — good and bad |
| **References** | Notion ticket IDs, related ADRs, related PRs |

## Tone

Terse and normative. Decision-record style. Not narrative. Present-tense for the decision: "status MUST be derived from…", not "we decided to derive status from…".

## Status lifecycle

- **Proposed**: decision is under discussion; not yet authoritative.
- **Accepted**: decision is final and normative.
- **Superseded by ADR-NNNN**: a later decision overrides this one. Update the Status line of the older ADR; do not delete it.

## When to write an ADR

Write an ADR when:
- A choice affects how any two SDKs must behave identically (cross-SDK contract).
- A choice would surprise a future implementer reading the code without context.
- A choice explicitly rejects a reasonable alternative that may recur.
- A governance principle is being applied in a non-obvious way.

Do not write an ADR for:
- Pure implementation details with no protocol-contract consequence.
- Decisions that are fully self-evident from the spec.
- Decisions that belong in a single repo's own `docs/decisions/`.

## Index

| ADR | Title | Status | Date |
|---|---|---|---|
| [0001](0001-architecture-decision-record-convention.md) | Architecture Decision Record convention | Accepted | 2026-04-26 |
| [0002](0002-receipt-fingerprint-formula-cv-dispatched.md) | Receipt fingerprint formula: cv-dispatched (12/14/16/20-field) | Accepted | 2026-04-19 |
| [0003](0003-status-derivation-from-enforcement-action.md) | Status derivation from Enforcement.action (4-action mapping) | Accepted | 2026-04-19 |
| [0004](0004-nfc-normalization-scope-in-canonical-json.md) | NFC normalization scope in canonical JSON | Accepted | 2026-02-18 |
| [0005](0005-authority-matching-exact-plus-glob.md) | Authority matching: exact + opt-in glob (rejected: substring) | Accepted | 2026-04-22 |
| [0006](0006-dict-mutation-pattern-enforcement-at-construction.md) | Dict-mutation pattern (Option B): enforcement at construction, never post-hoc | Accepted | 2026-04-20 |
| [0007](0007-cloud-ingestion-delegates-crypto-to-sdk.md) | Cloud ingestion delegates crypto to SDK verifier; quarantines unsigned | Accepted | 2026-04-22 |
| [0008](0008-content-mode-as-ingestion-contract.md) | content_mode is an ingestion CONTRACT, not server-side redaction | Accepted | 2026-04-22 |
| [0009](0009-governedtools-removed-scope-in-constitution.md) | governedTools removed; per-tool governance scope (if reintroduced) lives in the constitution | Accepted | 2026-04-26 |
| [0010](0010-dist-regression-test-via-package-exports.md) | Dist regression test discipline: test through package-exports, not src | Accepted | 2026-04-21 |
| [0011](0011-claudemd-to-agentsmd-migration.md) | CLAUDE.md → AGENTS.md migration; thin router committed, not gitignored | Accepted | 2026-04-26 |
