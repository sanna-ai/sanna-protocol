## [Unreleased] -- 2026-04-30 (SAN-378 Prompt A)

### Changed
- `fixtures/manifest-content-vectors.json` MC-006 (cli surface) expected output: added `suppression_reasons: {"rm": "cannot_execute"}` to `surfaces.cli`. Aligns the fixture with v1.5 spec Section 2.20.2 which has always required `suppression_reasons` in cli surface shape.
- MC-007 (http surface) expected output: added `suppression_reasons: {"https://malicious.com/*": "cannot_execute"}` to `surfaces.http`. Same alignment.

### Compatibility
- **Receipt fingerprint compatibility:** post-SAN-378 receipts will include `suppression_reasons` in cli/http surfaces (per v1.5 Section 2.20.2). This changes the canonical JSON shape and therefore the receipt fingerprint when cli/http surfaces have suppressed entries. Existing signed receipts remain valid (signature is over what was emitted). Re-emission of the same input post-upgrade produces a different fingerprint than pre-upgrade. Verifiers should accept receipts as-emitted; cross-version fingerprint replay is not a conformance test.
- **SDK consumers MUST upgrade in lockstep with this fixture update.** sanna-repo and sanna-ts SDKs at the pre-SAN-378 manifest.py / manifest.ts implementation will FAIL the behavior-parity gate when running test_manifest_content_vectors against this updated fixture (their `_generate_cli_surface` / `_generate_http_surface` do not emit `suppression_reasons` yet). The SDK fixes ship in SAN-378 Prompt B (sanna-repo) and Prompt C (sanna-ts), with each SDK bumping its `spec/` submodule pin to this prompt's merge commit at the same time as the implementation update.
- The SDKs' current `spec/` submodule pins (sanna-protocol f89c8c9 = post-SAN-376/377) are NOT auto-updated by this PR. Each SDK's main branch CI continues to pass against its current pin. SAN-378 Prompt B + Prompt C explicitly bump the pins.

### Tickets
- SAN-378 Prompt A (this entry)
- Companion: SAN-378 Prompt B (sanna-repo, blocked on this), SAN-378 Prompt C (sanna-ts, blocked on Prompt B), SAN-376 (cross-SDK fixture origin, annotated post-done), SAN-202 + SAN-203 (Python + TS manifest origins, annotated post-done x3 collectively), SAN-377 (spec clarification, merged), SAN-382 (R1 schema-rule enforcement gap, deferred Backlog).

## [Unreleased] -- 2026-04-30 (SAN-377)

### Changed
- Spec Section 2.14 (Content mode and the com.sanna.manifest extension): clarified per-content_mode redaction rules. Under `content_mode=redacted`, tool names and patterns become the literal string `<redacted>`, `suppression_reasons` is OMITTED from each surface sub-object, and a new `aggregate_suppression_reasons: list[str]` field is REQUIRED in each surface sub-object that has suppressed entries (aligned by index with the corresponding suppressed list). Under `content_mode=hashes_only`, tool names and patterns become lowercase 64-hex SHA-256 of the cleartext value (via canonical `hash_text` helper); `suppression_reasons` keys become the same hashes; values remain cleartext reason enum strings. Resolves the dict-key ambiguity that prevented SAN-202 + SAN-203 from implementing redaction without information leak.
- Spec Section 2.20.2 (com.sanna.manifest required shape): documented the new `aggregate_suppression_reasons` optional field; cross-references Section 2.14 for per-content_mode rules.
- `schemas/receipt.schema.json`: added two new conditional rules (R1 for `content_mode=redacted`, R2 for `content_mode=hashes_only`) to the top-level `allOf` array. Pre-validated with four test receipts (full cleartext, redacted-correct, redacted-bug, hashes_only); rules behave as designed -- redacted-correct passes, redacted-bug (SAN-202/SAN-203 inherited shape) fails.

### Compatibility
- Backward-compatible for receipts with `content_mode=full` or absent (the existing case): no change. The new rules only apply when `content_mode` is explicitly set to `redacted` or `hashes_only`.
- Existing v1.5 receipts WITHOUT content_mode set continue to validate unchanged.
- SDKs implementing redaction now have an unambiguous spec target. SAN-206 (Python) and SAN-209 (TS) are unblocked on this clarification.

### Tickets
- SAN-377 (this entry)
- Companion: SAN-206 (Python redaction implementation, blocked on this), SAN-209 (TS mirror, blocked on this), SAN-202 (Python manifest origin, annotated post-done), SAN-203 (TS manifest origin, annotated post-done), SAN-204 (v1.5 spec foundations, merged), SAN-376 (cross-SDK manifest content fixture, merged).

## [Unreleased] -- 2026-04-30 (SAN-376)

### Added
- New cross-SDK test vector file `fixtures/manifest-content-vectors.json` with 8 vectors (MC-001..MC-007, MC-009) exercising `generate_manifest()` content correctness. Both Python (sanna) and TypeScript (sanna-ts) SDKs must produce byte-identical outputs for every vector. Resolves the manifest-content-assertion gap surfaced in SAN-203 PR #27 where integration tests validated receipt structure but not content. Vectors cover: cannot_execute halt; must_escalate with escalation_visibility=visible; must_escalate with escalation_visibility=suppressed; fail-closed on null constitution; determinism/sorting; CLI-only surface; HTTP-only surface; empty mcp_tools key-presence semantics.
- `fixtures/README.md` new "Cross-SDK Test Vectors" section documenting `manifest-content-vectors.json`, `authority-matching-vectors.json`, and `multi-surface-vectors.json`. Closes a pre-existing audit-trail gap where these vector files were undocumented.

### Compatibility
- No spec changes. No schema changes. No SDK code changes in this PR.
- Vector file `version` field is `"1.5"`, indicating the protocol spec version the vectors target.
- Constitutions embedded in vectors are unsigned dicts; signature verification is out of scope for manifest content tests (verified separately by receipt-fixture tests).
- MC-008 (surfaces_filter exercise) is intentionally absent from SAN-376; ships in SAN-206 alongside the surfaces-filter implementation in `manifest.py` / `manifest.ts`.

### Tickets
- SAN-376 (this entry)
- Companion: SAN-206 (Python interceptors + gateway retrofit + content assertions, blocked on this), SAN-209 (TS mirror, blocked on SAN-206), SAN-202 (Python manifest origin, merged), SAN-203 (TS manifest origin, merged), SAN-204 (v1.5 spec, merged).

# Changelog

All notable changes to the Sanna Protocol specification will be documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Protocol versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] -- 2026-04-30

### Added
- Section 2.7: MODIFY parameter recording fields (`tool_input_original`,
  `tool_input_transformed`, `transformations_applied`) for the new
  `modify_with_constraints` authority decision. Required when a receipt's
  `authority_decisions` includes a `modify_with_constraints` decision.
- Section 2.12: Normative binding text for invocation_anomaly receipts.
  `parent_receipts` MUST contain the active session_manifest's
  `full_fingerprint`.
- Section 2.14: content_mode handling for the com.sanna.manifest
  extension. Tool names and patterns are obscured under
  `content_mode=redacted` or `hashes_only`.
- Section 2.15.1: Ten new event_type values activated --
  `session_manifest`, `invocation_anomaly`, `invocation_modified`,
  `invocation_deferred`, plus six CLI/API surface variants. event_type
  remains optional; conditional rules apply for new event_types.
- Section 2.16.1: enforcement_surface enum gains `"mixed"` for cross-
  surface session_manifest receipts.
- Section 2.16.3: Explicit status semantics for the new event_types.
- Section 2.19 NEW: `agent_identity` field for AARM R6 full conformance.
  Required at cv=10. Fingerprint position 21.
- Section 2.20 NEW: com.sanna.manifest extension namespace shape +
  determinism rules + snake_case key convention.
- Section 2.21 NEW: suppression_reason enum (7 stable values).
- Section 4.1: Fingerprint formula extended to 21 fields at cv=10.
- Section 6.7 NEW: Static composition normative rules (Phase 1).
- Section 6.8 NEW: AARM Conformance skeleton (full mapping in SAN-361).
- constitution.schema.json: `escalation_visibility` in
  `authority_boundaries`; `composition` top-level section. Both backward-
  compat optional.

### Changed
- Spec markdown renamed from `sanna-specification-v1.4.md` to
  `sanna-specification-v1.5.md`. Git history preserved via rename.

### Compatibility
- cv=9 receipts continue to validate against the receipt schema
  (legacy-acceptance preserved).
- Existing constitutions without `composition` / `escalation_visibility`
  validate against the new constitution.schema.json (backward compat).
- This spec landing does NOT activate cv=10. SDKs flip CHECKS_VERSION
  9 -> 10 in SAN-370. Until SAN-370 lands, no cv=10 receipts exist;
  the cv=10 schema rules are no-ops on existing cv=9 receipts.

### Migration
- See `docs/migration/cv9-to-cv10.md` (lands in SAN-371) for cv=10
  transition guidance.

### Tickets
- SAN-204 (this entry)
- See companion tickets SAN-369 (MODIFY in SDKs), SAN-370 (agent_identity
  + cv=10 in SDKs), SAN-371 (verifier cv-aware behavior + migration memo).

## [1.4.0-errata-A] - 2026-04-21

### Changed (Breaking: Appendix D authority matching semantics)

- **Appendix D §D.3 authority matching rule changed from bidirectional
  substring to exact + opt-in glob.** The original §D.3 specified that
  action `a` matches pattern `p` if `p` is a substring of `a` OR `a` is
  a substring of `p`. This is replaced by: (a) if `p` contains no `*`,
  match iff `p == a` after normalization (with separatorless fallback for
  exact stripped comparison only -- NOT substring containment); (b) if `p`
  contains `*`, match iff the normalized `a` satisfies the shell-style
  glob `p` (anchored full match, `*` only).

  **Breaking for third-party implementers who read the original 1.4 spec
  Appendix D:** If you implemented bidirectional substring matching, update
  your implementation to exact + glob matching. Substring matches that were
  not exact will now return false unless covered by a glob pattern.

  **Migration:** To restore broad-match behavior for a pattern `p` that
  previously relied on substring matching, replace `p` with `*p*` (or the
  appropriate prefix/suffix glob) in the constitution's authority
  boundaries. Example: `patch` → `*patch*` to match `api.patch.page`.

- **New fixture file `fixtures/authority-matching-vectors.json`** (21
  vectors): normative cross-SDK contract for authority matching. Both
  Python and TypeScript SDKs MUST return the same decision for every
  vector. Vector categories: exact match (E-001-E-004), exact non-match
  including F-005 repro (N-001-N-004), glob match (G-001-G-004), glob
  non-match (G-005-G-006), normalization robustness (R-001-R-002),
  separatorless fallback (S-001-S-002), degenerate/empty (D-001-D-003).

- **VERSIONING.md**: new "Errata for appendix-level behavioral
  clarifications" section documents the convention under which this
  errata is published. SAN-224 is the first application.

### Documentation (SAN-225)

- **Section 13.1 item 8 narrowed:** NFC normalization applies at the
  `hash_text()` boundary (fingerprint construction and text-mode
  hashing), not recursively within `hash_obj()` /
  `canonical_json_bytes()` inputs. Matches Section 3.1 and ADR-004
  (decided 2026-02-18). Not a breaking change -- reference SDKs
  (sanna v1.3.0, sanna-ts 1.4.0) have always implemented this scope.
  Third-party implementers building to the previous Section 13 text
  should verify their canonical JSON paths do not eagerly NFC-normalize
  strings inside nested objects.

## [1.4.0] - 2026-04-20 (fixtures regenerated 2026-04-20)

### Added
- Required top-level field `tool_name` (enum: `"sanna"`, `"sanna-ts"`).
  Identifies the SDK implementation that emitted the receipt. Required
  at checks_version >= 9. Registered values extensible via spec PR for
  third-party SDKs. Participates in fingerprint as field 17 at cv=9.
- Optional top-level fields `agent_model`, `agent_model_provider`,
  `agent_model_version`. Capture the LLM model the agent was running
  on when the receipt was generated. Nullable for explicit opt-out.
  Absent-vs-null distinction is normative per Section 2.18.4 (see spec).
  Participate in fingerprint at positions 18-20 as
  `hash_text(value)` or `EMPTY_HASH` if null/absent.
- Section 2.17: documents `tool_name` field -- purpose, enum values,
  registration process for third-party SDKs (submit a spec PR),
  design rationale (identity/version separation).
- Section 2.18: documents `agent_model*` fields -- purpose, opt-out
  semantics (absent vs null vs string), normative requirement that
  aggregators MUST respect the three-way distinction, concrete
  absent-vs-null JSON example.
- Section 13 rewritten to describe cv-based dispatch correctly (closes
  a Codex review finding where Section 13 referenced a stale 14-field
  formula despite Section 4.1 having updated to cv=8 → 16 fields).

### Changed
- Canonical fixtures `fixtures/receipts/*.json` regenerated at v1.4
  shape using `sanna` Python SDK v1.4.0 (SAN-222 v1.4-B2). Fixtures
  now include `tool_name`, `agent_model`, `agent_model_provider`,
  `agent_model_version`. `full-featured.json` exercises the
  captured-model path (`agent_model="claude-opus-4-7"`); other three
  fixtures use `agent_model=null` for explicit opt-out coverage.
  Old v1.3 fixtures archived under `fixtures/receipts/archive/v1.3/`.
- `CHECKS_VERSION` incremented from `"8"` to `"9"` to reflect the
  fingerprint formula expansion from 16 to 20 fields.
- JSON Schema `$id` bumped from `receipt/v1.3.json` to
  `receipt/v1.4.json`.
- Spec file renamed `sanna-specification-v1.3.md` →
  `sanna-specification-v1.4.md`.
- Fingerprint algorithm description updated: 16-field formula at
  cv=8 becomes 20-field formula at cv=9. Verifiers MUST dispatch on
  `checks_version` to select field count. Legacy cv values (5, 6, 7,
  8) unchanged.

### Normative additions
**Tool-name enum:** valid values for `tool_name` at cv >= 9 are
registered in the spec. Current values: `"sanna"`, `"sanna-ts"`.
Third-party implementers MUST NOT use unregistered values; register
via spec PR.

**Agent-model opt-out semantics:** the tri-valued absent/null/string
distinction for `agent_model` fields is normative. Aggregators MUST
NOT conflate absent with null. Implementers who provide aggregation
features MUST document how each value is treated.

## [1.3.0] - 2026-04-18

### Added
- `enforcement_surface` required top-level field: enum of four values (`middleware`, `gateway`, `cli_interceptor`, `http_interceptor`). Makes receipts self-describing about which governance surface produced them. Participates in fingerprint computation as field 15.
- `invariants_scope` required top-level field: enum of four values (`full`, `authority_only`, `limited`, `none`). Makes receipts self-describing about which invariants actually ran. Participates in fingerprint computation as field 16.
- Status derivation mapping (normative, Section 2.16.3): when `invariants_scope` is `authority_only` or `none`, `status` MUST be derived from `enforcement.action` -- `halted`→`FAIL`, `warned`→`WARN`, `allowed`→`PASS`, `escalated`→`WARN`. Rationale for `escalated→WARN`: escalated actions are flagged-not-greenlit; approval is a downstream receipt. Reporting PASS would imply governance allowed this, which is false until approval lands.
- Cross-field consistency rule (normative, Section 4.6): verifiers MUST assert that `status` matches `enforcement.action` per the derivation mapping. Mismatch MUST produce a verification error. A receipt that passes schema validation but violates this rule is cryptographically valid but semantically defective.
- 16-field fingerprint formula: two new fields (`enforcement_surface_hash` at position 15, `invariants_scope_hash` at position 16) participate in fingerprint computation.
- Architectural asymmetry note (non-normative, Section 2.16.4): Python `generate_receipt()` invokes C1-C5 by default with `skip_default_checks=True` opt-out for interceptor surfaces; TypeScript `generateReceipt()` does not invoke C1-C5 automatically (caller invokes `runCoherenceChecks()` separately). Both paths are spec-compliant at v1.3.
- `checks_version` version history table (Section 4.4) documenting values `"5"` through `"8"` with per-version semantics.

### Changed
- `checks_version` incremented from `"7"` to `"8"` to reflect the fingerprint formula expansion from 14 to 16 fields.
- JSON Schema `$id` bumped from `receipt/v1.2.json` to `receipt/v1.3.json`.
- Spec file renamed `sanna-specification-v1.2.md` → `sanna-specification-v1.3.md`.
- Fingerprint algorithm description updated: 14-field formula becomes 16-field formula at `checks_version="8"`. Verifiers MUST dispatch on `checks_version` to select field count.

### Normative statement
**v1.2 was never released in SDK form.** The v1.2 spec document was published but no SDK release implemented `spec_version="1.2"` semantics. Any receipt in the wild claiming `spec_version="1.2"` is spurious and MUST be treated as such by verifiers. SDKs skip directly from `"1.1"` to `"1.3"`.

## [1.2.0] - 2026-03-14

### Fixed
- **Section 4.1 fingerprint formula corrected to match reference implementations.**
  The previous formula listed `spec_version`, `tool_version`, `timestamp`,
  `agent_id` (correlation_id), `query_hash`, and `status` as literal string
  fields, and omitted `enforcement_hash`, `coverage_hash`, `authority_hash`,
  `escalation_hash`, and `trust_hash`. The reference implementations (sanna
  v1.0.0, sanna-ts v1.0.2) use the correct 14-field formula with
  `correlation_id` as field 1 and structural hashes for fields 5-14. The
  spec now documents the formula that all implementations produce. No
  breaking change: no third-party implementation used the incorrect formula.

### Added
- `event_type` optional receipt field: identifies governance surface and
  enforcement outcome (MCP, CLI, API) with nine enumerated values. Aligned
  with GCD Layer 4 (Enforcement) event types.
- `context_limitation` optional receipt field: documents what the governance
  boundary observes, with five enumerated values (`gateway_boundary`,
  `cli_execution`, `cli_no_justification`, `api_execution`,
  `api_no_justification`).
- Receipt Triad specification for CLI execution boundary (Section 7.6):
  `input_hash` from `{args, command, cwd, env_keys}`, `action_hash` from
  `{exit_code, stderr, stdout}`.
- Receipt Triad specification for API execution boundary (Section 7.7):
  `input_hash` from `{body_hash, headers_keys, method, url}`, `action_hash`
  from `{body_hash, response_headers_keys, status_code}`.
- `cli_permissions` constitution block: binary-level governance with
  strict/permissive modes, argv pattern matching, per-command authority.
- `api_permissions` constitution block: URL pattern governance with method
  filtering, strict/permissive modes, per-endpoint authority.
- Multi-surface test vectors (`fixtures/multi-surface-vectors.json`).
- Updated constitution templates with multi-surface governance blocks.
- GCD event type reservation note for future Layer 1-3 events.

## [1.1.0] - 2026-03-05

### Added
- `parent_receipts` field: array of `full_fingerprint` strings for receipt
  chaining in multi-step workflows. Participates in fingerprint computation
  (field 13).
- `workflow_id` field: opaque string grouping related receipts into a
  workflow. Participates in fingerprint computation (field 14).
- `content_mode` field: enum (`full`, `redacted`, `hashes_only`) declaring
  content handling for Cloud. Metadata only -- does NOT participate in
  fingerprint.
- `content_mode_source` field: origin of content_mode value (`local_config`,
  `cloud_tenant`, `override`). Metadata only -- does NOT participate in
  fingerprint.
- Gateway extension namespace appendix (Appendix E): formalizes
  `com.sanna.gateway` extension schema for interoperability
- Canonical YAML hash specification (Appendix F): documents how
  constitutions are hashed for receipt linking
- 1,296 cross-language canonicalization test vectors
  (`fixtures/canonicalization-vectors.json`): Unicode NFC, key ordering,
  null/empty handling, integer boundaries, array ordering, whitespace/escaping,
  round-trip verification, 14-field fingerprint computation

### Changed
- **BREAKING:** Fingerprint formula expanded from 12 fields to 14 fields.
  No backward compatibility with the 12-field formula.
- `checks_version` incremented from `"5"` to `"6"` to reflect the
  fingerprint algorithm change
- All golden receipt fixtures regenerated with 14-field fingerprint
- JSON Schema updated (`receipt.schema.json`) with four new fields
- Spec version bumped from `1.0` to `1.1`

## [1.0.2] - 2026-02-17

### Added
- Redaction Marker schema (Section 2.11): marker structure, `original_hash`
  computation, pre-existing marker injection guard, file naming convention,
  hash recomputation rules
- Authority Name Normalization algorithm (Appendix D): NFKC + camelCase
  splitting + separator normalization + casefold + dot-join, with 16 test
  vectors
- HMAC token binding corrections (Section 8.2): `esc_` prefix on escalation
  IDs, Python-default separators for `args_digest`

### Changed
- Canonical JSON cross-language guidance: Go HTML-escaping warning, float
  rejection clarified for Go/Rust number parsing
- Base64 pinned to RFC 4648 standard with padding (Section 5.1)
- Exit code accumulation rule: highest-priority code wins (Section 9.2)

## [1.0.1] - 2026-02-15

### Added
- 28 precision fixes from cross-platform security review
- Key ID computation from raw Ed25519 bytes (not DER)
- NFC normalization documentation
- Float rejection in signing contexts
- Threat model (Section 12.3)
- Schemas for `authority_decisions`, `escalation_events`,
  `source_trust_evaluations`, `identity_verification`
- Key file encoding specification (PKCS#8 PEM / SubjectPublicKeyInfo PEM)
- `correlation_id` pipe character constraint

### Changed
- `hash_text` default truncation corrected to 64 characters
- Status computation handles all severity levels
- Receipt Triad hashing made byte-precise
- `checks_hash` ordering and null key rules clarified

## [1.0.0] - 2026-02-10

### Added
- Initial specification release
- Receipt format with 12-field fingerprint construction
- Constitution format (YAML) with boundaries, invariants, halt conditions
- Sanna Canonical JSON (RFC 8785 derived, NFC normalized)
- Ed25519 signing for receipts and constitutions
- Verification protocol with exit codes
- Evidence bundle format
- Escalation and approval chain with HMAC-SHA256 token binding
- Receipt Triad (input_hash, reasoning_hash, action_hash)
- JSON Schema (2020-12) for receipts and constitutions
- Golden test fixtures for cross-language conformance
- Constitution templates (privacy-focused, developer, locked-down)
- HTTP header conventions for REST API receipt transport

### Field Renames (from pre-1.0)
- `schema_version` renamed to `spec_version`
- `trace_id` renamed to `correlation_id`
- `coherence_status` renamed to `status`
- `halt_event` renamed to `enforcement`
