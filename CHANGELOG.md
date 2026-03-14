# Changelog

All notable changes to the Sanna Protocol specification will be documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Protocol versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  content handling for Cloud. Metadata only — does NOT participate in
  fingerprint.
- `content_mode_source` field: origin of content_mode value (`local_config`,
  `cloud_tenant`, `override`). Metadata only — does NOT participate in
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
