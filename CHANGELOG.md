## [Unreleased] -- 2026-05-11 (SAN-249 PR 1 of 2)

### Added

- **`content_mode_source` enum** now accepts `"middleware_redaction_config"` (in addition to the existing `"local_config"`, `"cloud_tenant"`, `"override"`). The new value distinguishes redaction provenance set by the `@sanna_observe` middleware decorator's `redaction_config` parameter from local-file configuration. Schema: `schemas/receipt.schema.json`. Spec inline references: section 2.2 and section 2.14.

### Why this matters

SAN-249 PR 2 of 2 (sanna-repo) ports spec section 2.11 redaction primitives from the gateway path into a top-level `sanna/redaction.py` module and wires them into `@sanna_observe`. The middleware emission path needs a distinct `content_mode_source` provenance value to preserve audit-trail granularity. Without this enum addition, middleware-applied redaction would have to share the `"local_config"` provenance with YAML-file-driven gateway redaction, losing the auditor's ability to distinguish decorator-supplied configuration from local-file configuration.

This PR is the cross-repo prerequisite. The consumer-side change (sanna-repo) lands in SAN-249 PR 2 of 2 (sanna-ai/sanna PR #66).

### Audit-trail note (CI cross-SDK smoke expected failure)

The sanna-protocol CI cross-SDK smoke step explicitly checks that sanna-repo's operational schema mirror at origin/main matches the submodule schema at this PR's HEAD. By design this fails when a protocol PR adds a schema change before the consumer SDK has its operational copy updated. The expected resolution is admin merge of this PR followed by the consumer-side PR (SAN-249 PR 2 of 2 in sanna-repo) updating both the submodule pin AND the operational mirror in one commit.

Cross-SDK parity is restored when the consumer-side PR merges. No spec-version bump needed -- this is an additive schema change (enum extension, no breaking changes to existing receipts that use other source values).

## [Unreleased] -- 2026-05-11 (SAN-283)

### Changed

- **`spec/sanna-specification-v1.5.md`**: RFC 7322 style audit pass.
  Added Abstract section before Section 1. Updated Section 1.2
  Conventions to cite BCP 14 [RFC2119] [RFC8174] per current IETF
  requirement; added "NOT RECOMMENDED" to the conventions word list
  for canonical-template alignment (not used in spec body, included
  for completeness). Expanded acronyms NFC and AARM at first use
  (lines 292 and 517). Replaced Unicode arrows in prose with ASCII
  `->`. Added language tags to previously-unlabeled fenced code
  blocks. Annotated 8 example blocks with normative or informative
  classification.

### Out of scope (tracked separately)

- References section split into Normative / Informative -- SAN-284.
- IANA Considerations section -- SAN-285.
- IPR / BCP 78/79 boilerplate / Status of This Memo / Note Well --
  SAN-286.
- Author info and Acknowledgments -- SAN-287.
- Prose line-wrap to <=72 chars (217 long prose lines remain) --
  deferred to atomic kramdown-rfc transform in SAN-290.

### Why this matters

RFC 7322 (Style Manual) defines editorial conventions IETF RFCs
follow. Conforming the spec source to those conventions before
kramdown-rfc conversion reduces the diff during format conversion
and produces a draft that an IETF reviewer reads as native-style on
first pass. Prerequisite for the Internet-Draft submission stream
(SAN-290, SAN-291).

## [Unreleased] -- 2026-05-10 (SAN-493 PR 1 of 3)

### Changed

- **`tools/generate_state_doc.py`**: drops git-SHA from the
  `docs/state.md` header. The pre-fix header was
  `<!-- generated: TS  git-sha: SHA -->`; post-fix it is
  `<!-- generated: TS -->`. The SHA was always one-commit-stale
  because regen runs pre-commit (per the sealed-gate pattern,
  HEAD at regen time is the parent commit), so the embedded SHA
  never matched the commit that landed the state.md update. Now
  the file contains only derived state from sources of truth
  (spec_version, checks_version, schema list, fixture count,
  latest CHANGELOG entry); commit SHAs come from `git log`.
- **`git_sha()` function removed** from `generate_state_doc.py`
  (was used only for the header; now dead code).
- **`generate_full()` signature simplified** from
  `(root, sha, timestamp)` to `(root, timestamp)`. Internal API
  change; no external callers.
- **`main()` print statement** drops the `sha=...` field; keeps
  spec / cv / fixtures.

### Added

- **`test_state_md_header_does_not_contain_git_sha`** in
  `tests/test_generate_state_doc.py`: regression guard asserting
  the `git-sha:` substring does NOT appear in the regenerated
  header. Catches a future re-introduction of the embedded SHA.

### Why this matters

- Eliminates a known one-commit-stale audit artifact in state.md.
  Auditors reading the file previously saw a SHA that didn't match
  the commit it landed in; post-fix, the file contains no SHA and
  refers auditors to `git log` for that information.
- Removes the extra round-trip ("regen post-first-commit") that
  Sonnet workarounds previously required (see SAN-492 PR 1
  `ca2de52`). One-commit PRs become possible again for state-only
  changes.
- The fix is mechanism-only: count + version fields on a clean
  tree are byte-identical to pre-fix (fixtures=37, schemas=2,
  spec=v1.5). No customer-visible behavior.

### Out of scope (separate PRs in this ticket)

- `sanna-repo/tools/generate_state_doc.py` -- SAN-493 PR 2 of 3.
- `sanna-ts/tools/generate_state_doc.py` (or equivalent) --
  SAN-493 PR 3 of 3.

### Cross-references

- SAN-492 PR 1 (sanna-protocol PR #36) -- where this surfaced,
  workaround commit `ca2de52`.
- SAN-498 -- prior generator cleanup in the same file.
- Memory rule `feedback_state_md_hard_gate_before_commit.md`.
- Memory rule `feedback_state_md_regen_commands_per_repo.md`.

## [Unreleased] -- 2026-05-10 (SAN-498)

### Changed

- **`tools/generate_state_doc.py`**: file enumeration now uses
  `git ls-files` pathspec instead of `Path.glob` / `Path.rglob` in
  three functions:
  - `get_spec_version`: `git ls-files spec/sanna-specification-v*.md`
  - `get_schemas`: `git ls-files schemas/*.json`
  - `count_fixtures`: `git ls-files fixtures/`
  Untracked working-tree files (macOS Finder duplicates like
  `<name> 2.<ext>`, editor temps, untracked `.DS_Store`) can no
  longer inflate state.md counts and cause local-vs-CI drift.

### Added

- **`tests/test_generate_state_doc.py`** with four tests:
  - Three regression guards asserting generator output matches
    `git ls-files` output for fixtures, schemas, and spec.
  - One active-verification test
    (`test_count_fixtures_excludes_untracked_pollution`) that creates
    an untracked sentinel file in `fixtures/` and asserts
    `count_fixtures` returns the baseline (not baseline+1). This
    test fails under `Path.glob` and passes under `git ls-files`,
    actively proving the bug fix beyond what regression guards catch.

### Why this matters

- Closes a recurring state.md drift source surfaced 2026-05-08
  during SAN-491 dispatch (Sonnet halted at Phase 0.2 because
  generator counted 39 fixtures instead of 37; root cause was two
  untracked Finder duplicates in `fixtures/keypairs/`).
- state.md is an auditor-facing snapshot referenced from README's
  Documentation table. Drift between local and CI undermines the
  audit-evidence trust the snapshot is meant to establish.
- Fourth application of the "generators must use git ls-files"
  pattern across the Sanna repos (sanna-repo, sanna-ts,
  sanna-cloud test counts, now sanna-protocol). Memory rule
  `feedback_generators_must_use_git_ls_files_not_filesystem_glob.md`
  pre-existed; this PR closes the recurrence on sanna-protocol.

### Out of scope

- Cleanup of tracked `schemas/.DS_Store` -- pre-existing macOS
  metadata in the repo; the `*.json` pathspec filters it correctly
  in both pre-fix (Path.glob) and post-fix (git ls-files) code.
  Separate hygiene ticket.
- Path.glob audits in `generate_fixtures.py` and
  `generate_test_vectors.py` (root-level generators in
  sanna-protocol). Notion ticket SAN-498 is scoped to
  `tools/generate_state_doc.py`. If those generators have similar
  issues, file as separate tickets.

### Cross-references

- SAN-491 -- where this surfaced (Sonnet HALT at Phase 0.2)
- User memory rule:
  `feedback_generators_must_use_git_ls_files_not_filesystem_glob.md`

## [Unreleased] -- 2026-05-08 (SAN-491)

### Added

- **Cross-SDK consumption smoke gate in CI** (`.github/workflows/ci.yml`).
  Two new jobs (`cross-sdk-smoke-python`, `cross-sdk-smoke-typescript`) check
  out sanna-ai/sanna and sanna-ai/sanna-ts at main, override each consumer's
  `spec/` submodule to the protocol PR's HEAD via
  `git fetch origin pull/<N>/head`, and run each consumer's spec-touching
  CI gates using the same commands and environment that consumer's own CI
  uses:
  - sanna-repo gates: schema parity diff (`spec/schemas/*` vs
    `src/sanna/spec/*`), `python -m pytest tests/ -v`, golden receipts
    verification via `sanna-verify`, example constitution verification via
    `sanna-sign-constitution`. All gated on `SANNA_ALLOW_TEMP_DB=1`.
  - sanna-ts gates: `npm run build`, then `npm test` with
    `SANNA_ALLOW_TEMP_DB=1`.
  Fails the protocol PR if any gate fails.
- New `## CI: Cross-SDK Smoke Gate` section in `README.md` documenting the
  gate's purpose, mechanics, failure interpretation, and local reproduction.

### Why this matters

Closes the consumer-CI detection gap surfaced during SAN-404 PR 1 -> PR 3
sequence (2026-05-06): protocol PR 1's forward-only key rotation deleted
`spec/fixtures/keypairs/test-author.key`, breaking 5 sanna-ts test modules
that loaded that file at module scope. The breakage went undetected from
PR 1 merge until PR 3 dispatch (~hours). The smoke gate moves detection
to protocol PR time. Goes beyond the original ticket scope by also catching
operational schema-mirror drift, golden-receipt fingerprint divergence, and
TS type-break (via `npm run build`) -- not just pytest-visible breaks.

### Tradeoffs

Protocol PR CI duration increases from ~3 minutes to ~10-15 minutes. The
two new jobs run in parallel after `validate-schemas` completes; total
end-to-end time is `validate-schemas` (~3 min) + max(smoke-python, smoke-ts)
(~10-15 min). Acceptable per the open-beta posture: correctness > velocity.

### Security posture

- Uses `pull_request` event only (NOT `pull_request_target`); CI runs without
  secrets, fetching public repos read-only.
- Each smoke job declares `permissions: contents: read` (least-privilege
  GITHUB_TOKEN scope).
- Each smoke job declares `timeout-minutes: 30` (prevents runaway hangs).
- All action references pinned to specific commit SHAs with version comments.
- Submodule pin override is scoped to the smoke job's transient consumer
  checkout; does not affect protocol's own working tree or main pin.

## [Unreleased] -- 2026-05-07 (SAN-492)

### Changed

- **Schema MINOR bump 1.0.1 -> 1.1.0.** Mixed-class change:
  - Formalizes `cli_permissions.inspect_scripts` (boolean, default false) in
    the schema. The field exists in Python's CliPermissions today but was
    rejected by the schema's `additionalProperties: false` on cli_permissions
    -- a spec/schema/code drift now corrected.
  - Widens `provenance.signature.scheme` enum from
    `["constitution_sig_v1"]` to `["constitution_sig_v1", "constitution_sig_v2"]`
    to recognize the v2 canonical form. Verifiers MUST reject any other scheme.
  - Formalizes top-level `version` property (string, default "1.0"). The field
    is read by the Python SDK's signing path and used in v2 canonical bytes when
    != "1.0", but was previously rejected by `additionalProperties: false`.
  - Formalizes top-level `reasoning` property (object/null). The GLC reasoning
    config exists in Python's Constitution dataclass and gates on
    sanna_constitution >= "1.1", but was previously rejected by
    `additionalProperties: false`. Full sub-schema to follow as a separate PR.
  - Null-acceptance permissiveness expansion across 9 fields:
    `CliCommand.argv_pattern`, `CliCommand.description`, `CliCommand.escalation_target`,
    `CliInvariant.pattern`, `CliInvariant.condition`,
    `ApiEndpoint.methods`, `ApiEndpoint.description`, `ApiEndpoint.escalation_target`,
    `ApiInvariant.pattern`. Each field's type widens from singular to `[..., "null"]`.
  - The simultaneous PATCH-class permissiveness clarification rides along; semver
    picks the bigger bump (formalizing inspect_scripts, scheme enum widen, version,
    and reasoning are all MINOR-class -- new schema vocabulary for pre-existing SDK
    behavior).
- `sanna_constitution` schema version example bumps to `"1.1.0"` (plus retains
  prior versions for backwards-compat in YAML inputs).

### Added

- **Spec Section 5.3: Constitution Canonical Form Versions (v1, v2).**
  Documents the two canonical-form versions, the verifier-side dispatch on
  `provenance.signature.scheme`, the v1 frozen-per-SDK behavior, the v2
  unified union form (defaults emitted explicitly; nulls for absent
  Optional sub-fields), and the policy_hash vs constitution-signature
  scope asymmetry. Renumbers former 5.3-5.6 to 5.4-5.7 to accommodate.
- **Spec Section 13.6: Constitution Signable Vectors v2 (SAN-492).**
  Cross-SDK conformance requirement for the v2 form.
- `fixtures/constitution-signable-vectors-v2.json`: cross-SDK byte-equal
  contract for v2. 20 vectors cover the full union of Optional/default fields
  across structural blocks (must_escalate.target shapes inherited from SAN-490;
  cli_permissions including inspect_scripts; api_permissions; composition;
  version; reasoning; combined). Each vector specifies input, expected canonical
  JSON, and SHA-256 cross-check.
- `tools/generate_signable_vectors_v2.py`: deterministic regenerator and
  reference implementation for v2. SDK alignments must produce
  byte-identical output.

### Unexpected (schema/code gaps resolved)

- `version` and `reasoning` were absent from the schema despite being used in
  the Python SDK's signing path. Both are now formalized. Discovered when
  implementing v2 vector coverage -- vectors for these fields would have failed
  schema validation against the pre-bump schema. Reported in SAN-492 PR 1 of 3.

### Tickets

- SAN-492 (this entry; sanna-protocol portion -- adds cross-SDK byte-equal
  contract for v2 + schema MINOR bump + spec normative form). Companion
  sanna-repo PR (signing_version parameter + v1/v2 dispatch + regression
  test) and sanna-ts PR (same + add inspect_scripts to CliPermissions +
  add full ReasoningConfig type system + field-level default-emission
  alignment) follow as separate PRs.

## [Unreleased] -- 2026-05-07 (SAN-490)

### Changed

- **Schema permissiveness clarification.** `schemas/constitution.schema.json`
  now accepts `["string", "null"]` for `must_escalate.target.url` and
  `must_escalate.target.handler`, and `["object", "null"]` for
  `must_escalate.target` itself. The `sanna_constitution` schema version
  example bumps to `"1.0.1"`. This is a backwards-compatible PATCH-level
  bump: an absent optional field and an explicit `null` are semantically
  identical (no escalation URL or handler configured); the previous
  `"type": "string"` constraint was an over-strict validation, not a
  deliberate semantic choice. YAMLs at `1.0.0` continue to validate
  unchanged.

### Added

- `fixtures/constitution-signable-vectors.json`: cross-SDK byte-equal
  contract for `constitution_to_signable_dict`'s output. Five vectors
  cover `must_escalate.target` shapes (no optionals; url-only;
  handler-only; null target; all-fields). Each vector specifies an
  input Constitution dict, the expected canonical signable JSON bytes,
  and the SHA-256 of those bytes for cross-check.
- `fixtures/constitutions/with-authority-target.yaml`: representative
  constitution at `sanna_constitution: 1.0.1` exercising the new
  schema-permissive target shapes.
- `tools/generate_signable_vectors.py`: deterministic regenerator for
  the vectors file.
- Spec Section 6.9: normative canonical signable form for
  `authority_boundaries.must_escalate.target`.
- Spec Section 13.5: cross-SDK conformance reference for
  `fixtures/constitution-signable-vectors.json`.

### Tickets

- SAN-490 (this entry; sanna-protocol portion -- adds the cross-SDK
  byte-equal contract fixture, schema permissiveness clarification, and
  spec normative form). Companion sanna-ts canonicalization alignment
  (applies explicit null-include at `constitution.ts:691-696`) and
  sanna-repo regression test (asserts Python signable bytes match the
  fixture) land in separate PRs.

## [Unreleased] -- 2026-05-06 (SAN-404)

### Security

- **Test keypair rotation.** Both committed Ed25519 test PEM private keys
  in `fixtures/keypairs/` have been rotated and are now REVOKED:
    - `6edb993769fb606cdd56c47335970a0b42d163bcb44b21db416e6ec43963af61`
      (test-author, original) -- REVOKED
    - `02dd2d06eb03568accb742fc2a7ce751f2716627dd8c50773a2fcf53c6412de6`
      (test-attacker, original) -- REVOKED
  Both `.key` files have been deleted from the working tree (forward-only;
  git history retains the keys at the commits at which they were
  introduced -- see SECURITY.md "Test Key Rotation (SAN-404)" for the
  trust posture).
- **`generate_fixtures.py` no longer writes a private key to
  `fixtures/keypairs/`.** The private key now lives in a temporary
  directory for the script run and is discarded at exit. Only
  `test-author.pub` and `test-author.meta.json` are committed.
- **`tools/generate_bundle_fixtures.py` no longer writes the attacker
  private key to disk.** The attacker keypair is held in process memory
  and used directly to sign the forged-bundle fixtures. Only
  `test-attacker.pub` and `test-attacker.meta.json` are committed.
- **Pre-commit hook.** Added `.pre-commit-config.yaml` with
  `pre-commit/pre-commit-hooks` `detect-private-key` to block any future
  PEM private key from entering the repo. CI runs the same hook on PR.
- **GitGuardian config tightened.** Removed `**/test-author.key` and
  `*.key` allowlist entries in `.gitguardian.yaml`. With the rotation
  complete, no `*.key` file should ever appear under `fixtures/`.

### Changed

- `golden-hashes.json:test_key_id` rotates from
  `6edb993...3af61` to the new author key_id. Customers / SDK tests
  that read `data["test_key_id"]` from the golden file pick up the new
  value automatically. Tests with hardcoded references to the old hex
  string will need to update.
- `golden-hashes.json:test_attacker_key_id` rotates from
  `02dd2d0...12de6` to the new attacker key_id (same dynamic-read
  contract).
- `bundle-trust-vectors.json:genuine_key_id` and `attacker_key_id`
  rotate to match the new keypairs.
- `fixtures/constitutions/minimal.yaml:provenance.signature.key_id` and
  `fixtures/receipts/*.json:receipt_signature.key_id` re-signed with the
  new author key.
- `fixtures/receipts/archive/v1.2/`, `v1.3/`, `v1.4/` are
  byte-identical and were NOT regenerated -- archives are frozen
  historical evidence.

### Tickets

- SAN-404 (this entry; sanna-protocol portion). Cross-SDK consumption
  follows in companion sanna-repo and sanna-ts submodule pin bumps.

## [Unreleased] -- 2026-05-06 (SAN-406)

### Added
- `fixtures/redaction-vectors.json`: cross-SDK byte-equal contract for
  com.sanna.anomaly extension field-level redaction (spec Section 2.22.5).
  9 helper_vectors covering 3 content_mode values (full / redacted /
  hashes_only) x 3 anomaly surfaces (invocation_anomaly /
  cli_invocation_anomaly / api_invocation_anomaly). 6 verifier_vectors
  (NEGATIVE cases: raw value emitted under redacted/hashes_only mode ->
  marker check FAILS; positive cases derivable from helper_vectors).
  Both Python (sanna) and TypeScript (sanna-ts) SDKs MUST produce
  byte-identical helper output AND identical Check.status for every
  vector. Verifier check name is the snake_case STRING
  `"redaction_markers_correct"` in both SDKs per cross-SDK Check.name
  parity contract.
- Hashes_only-mode helper_vectors include canonical SHA-256 hex
  (lowercase) for the 3 sample inputs ("rm", "echo_echo",
  "https://internal.evil.com/*"). For pure ASCII inputs, canonical
  hash_text/hashContent (NFC + line-ending norm + whitespace norm + UTF-8
  + SHA-256) reduces to raw SHA-256, so the fixture's hex equals
  `hashlib.sha256(input.encode("utf-8")).hexdigest()`. Phase 2
  validation re-computes and asserts equality (typo + drift guard).

### Tickets
- SAN-406 PR 3 of 5 (this entry; sanna-protocol cross-SDK fixture).
  PR 1 (sanna-repo Python) merged at 817bf1a. PR 2 (sanna-ts TypeScript)
  merged at 77acc44. PR 4 (sanna-repo bump+consume) and PR 5 (sanna-ts
  bump+consume) follow.
- Related: SAN-487 (CRITICAL authority bypass). PR 4 + PR 5 will ADD
  new fixture-consumption tests that load this fixture and call the
  helper + verifier DIRECTLY (no interceptor traversal). Those NEW
  tests are INDEPENDENT of SAN-487. The 6 end-to-end integration tests
  skipped in PR 1 + PR 2 with SAN-487 cite remain skipped until SAN-487
  fixes the design gap.

## [Unreleased] -- 2026-05-05 (SAN-403)

### Added
- `fixtures/bundles/genuine.bundle.zip` and `fixtures/bundles/forged.bundle.zip`:
  cross-SDK test bundles covering the bundle-forge attack vector closed by
  SAN-403. The forged variant is end-to-end re-signed with a separate
  attacker keypair and packaged with the attacker's public key inside the
  zip.
- `fixtures/keypairs/test-attacker.{key,pub,meta.json}`: Ed25519 keypair
  used to construct the forge variant. Test use only.
- `fixtures/bundle-trust-vectors.json`: cross-SDK conformance contract,
  seven vectors covering all anchor modes (no anchor / matching / excluding
  / empty fails closed / forged self-consistent / forged caught by genuine
  anchor / sanity check that misconfigured anchor does not provide
  assurance).
- `tools/generate_bundle_fixtures.py`: deterministic regenerator for the
  bundle fixtures and vectors file. Idempotent on the keypair and on the
  vectors file output.
- `golden-hashes.json` adds top-level `test_attacker_key_id` alongside
  `test_key_id`.
- Spec Section 10.1 "Trust Anchor (Verifier-Side Allowlist)": full
  semantics of the `trusted_key_ids` parameter, CLI flag, env var, file
  format, and `trust_anchored` result field.
- Spec Section 12.3 threat model bullet on bundle self-attestation forgery
  and trust-anchor mitigation.
- Spec Section 13.4 "Bundle Trust Anchor Vectors (SAN-403)" conformance
  requirement.
- SECURITY.md "Bundle Verification Trust Anchor (SAN-403)" section.

### Changed
- Spec Section 10 verification table: 7 steps -> 8 steps. The 8th step is
  "Trust anchor", evaluated only when a trust anchor was supplied.

### Tickets
- SAN-403 PR 3 of 3 (this entry; protocol fixture + spec + SECURITY.md).
  PR 1 (Python SDK) and PR 2 (TypeScript SDK) already merged. Cross-SDK
  CI consumption of the vectors will land under follow-up tickets that
  bump the spec submodule pin in each SDK repo.

## [v1.5] -- 2026-05-03 (SAN-373)

### Fixed
- Spec Section 4.5 + fingerprint formula table: fixed stale cross-
  reference 'Section 2.17.2' -> 'Section 2.18.4' (agent_model opt-out
  semantics). Section 2.17.2 does not exist; the content lives in
  Section 2.18.4 'Opt-Out Semantics (Normative)'.

### Tickets
- SAN-373 (this entry).

## [v1.5] -- 2026-05-03 (SAN-372)

### Added
- fixtures/receipts/archive/README.md: extended with expected-failure
  documentation for v1.2/escalated.json (Sprint 15 cross-field rule).
- tests/test_archive_fixtures.py: regression guard asserting
  v1.2/escalated.json fails current schema with 'WARN' error.
  Guards against loosening the Sprint 15 cross-field integrity rule.

### Tickets
- SAN-372 (this entry).

## [v1.5] -- 2026-05-03 (SAN-383)

### Fixed
- receipt.schema.json: A1' rule added. agent_identity MUST be absent
  at checks_version in {6, 7, 8, 9} (pre-v1.5). Previously only
  enforced the forward direction (cv=10 requires agent_identity).
  Uses explicit enum (not 'not const 10') for forward-compat with
  cv=11+ which will also require agent_identity.

### Tickets
- SAN-383 (this entry).

## [v1.5] -- 2026-05-03 (SAN-381)

### Fixed
- receipt.schema.json: R1 rule tightened. aggregate_suppression_reasons
  now REQUIRED when tools_suppressed/patterns_suppressed is non-empty
  under content_mode=redacted. Previously only constrained shape if present.

### Tickets
- SAN-381 (this entry).

## [v1.5] -- 2026-05-02 (SAN-397 Prompt A)

### Added
- constitution.schema.json: authority_boundaries.anomaly_tracking
  optional object with per-surface boolean (cli, http). Default:
  disabled for both (backward compatible). Existing constitutions
  validate cleanly without the field.
- Spec Section 2.15.1: normative text clarifying that
  cli_invocation_anomaly and api_invocation_anomaly emission requires
  authority_boundaries.anomaly_tracking.{cli,http} = true. MCP
  invocation_anomaly remains unconditional.

### Compatibility
- Existing constitutions without anomaly_tracking validate cleanly.
- Constitution hash unchanged when anomaly_tracking is absent or at
  defaults (both false). No re-signing required.
- No SPEC_VERSION bump (additive in-place clarification).

### Tickets
- SAN-397 Prompt A (this entry; protocol half).
- Companion: SAN-397 Prompt B (Python interceptors), SAN-397 Prompt C
  (TS interceptors).

## [v1.5] -- 2026-05-02 (SAN-358 Prompt C)

### Added
- New fixture `fixtures/manifest/verifier-verdicts.json` with 15
  receipt vectors (VV-001 through VV-015) covering session_manifest
  (9 checks) and invocation_anomaly (3 checks) verifier verdict
  outputs. Each vector encodes the receipt input + expected check
  array (name, status, message). Both Python and TypeScript verifiers
  MUST produce these exact verdicts -- the formal cross-SDK byte-equal
  gate.
- Coverage: passing manifests (gateway/mcp), missing extension,
  unsorted lists (determinism), delivered/suppressed overlap (anti-
  enumeration integrity), unknown suppression_reason (WARN fallback),
  invalid suppression_reason (FAIL), keys mismatch, missing
  constitution_ref, enforcement_surface=mixed with too few surfaces,
  anomaly single-receipt WARN, anomaly receipt-set PASS/FAIL/
  informational variants.

### Cross-SDK
- This fixture is the audit artifact proving cross-SDK verdict parity.
  SOC 2 evaluators can verify: same receipt -> same verdict -> same
  message text across both SDK verifiers.

### Tickets
- SAN-358 Prompt C (this entry; closes SAN-358).
- Companion: SAN-358 Prompt A (Python, PR #46), SAN-358 Prompt B
  (TypeScript, PR #36).

## [v1.5] -- 2026-05-02 (SAN-395)

### Added
- Section 2.22 NEW: The com.sanna.anomaly Extension Namespace.
  Reserves the namespace for invocation_anomaly receipts. Documents
  required shape (attempted_tool / attempted_command /
  attempted_endpoint per surface variant), suppression_basis enum
  (session_manifest, policy_override, constitution_invalid), and
  content_mode interaction.
- receipt.schema.json: rule B3 (com.sanna.anomaly extension implies
  event_type is an anomaly variant) + rule B4 (anomaly event_type
  requires com.sanna.anomaly with suppression_basis).
- receipt.schema.json: extensions description updated to distinguish
  com.sanna.* reserved namespace (positive validation) from vendor
  extensions outside that namespace (ignored by verifiers).

### Compatibility
- Existing cv=9 and cv=10 receipts WITHOUT invocation_anomaly
  event_type are unaffected (B3/B4 rules are conditional; no-ops
  when event_type is absent or non-anomaly).
- Existing invocation_anomaly fixtures validate cleanly under B4
  (they already contain com.sanna.anomaly with suppression_basis).
- No SPEC_VERSION bump (additive in-place clarification, same
  pattern as SAN-377).

### Tickets
- SAN-395 (this entry)
- Origin: SAN-206 + SAN-209 (introduced com.sanna.anomaly without
  spec coverage). SAN-358 Prompt A (baked it into verifier contract).
- Unblocks: SAN-358 Prompt B (TS verifier mirror); SAN-397
  (CLI/HTTP anomaly emission).

## [Unreleased] -- 2026-05-02 (SAN-368)

### Added
- **Operational subsection** in spec Section 14 (`### 14.9 How to verify AARM conformance`) documenting how to invoke the `sanna-verify aarm` (Python) and `sanna verify-aarm` (TypeScript) CLIs. Includes JSON output schema, aggregate status semantics (PASS/PARTIAL/FAIL), per-requirement check table (R1-R6 with PASS/FAIL/PARTIAL/N/A conditions), exit-code semantics, cross-SDK verdict parity note, and example invocations.

### Tickets
- SAN-368 (this entry; sanna-protocol portion -- closes SAN-368)
- Predecessors:
  - sanna-repo SAN-368 portion (Python `sanna-verify aarm` CLI, MERGED at sanna-repo f2b53a5)
  - sanna-ts SAN-368 portion (TypeScript `sanna verify-aarm` CLI, MERGED)
  - SAN-361 (Section 14 AARM Conformance and Mapping spec section, MERGED)
- Cross-SDK CLI naming divergence (Python `sanna-verify aarm` vs TS `sanna verify-aarm`) tracked in a separate follow-up ticket (P2 Backlog).

## [Unreleased] -- 2026-05-02 (SAN-369)

### Added
- **Implementer's guide example for MODIFY authority decisions** (`docs/implementers-guide.md` Section 7.1). Documents the MODIFY decision pattern with Python and TypeScript code examples using the SAN-369 recording-infrastructure helpers. Includes the conceptual constitution rule pattern (rule engine ships in a follow-up), explains cross-SDK byte-equal parity, lists construction-time validation rules, and cross-references spec Section 2.7 + the SDK commits.

### Tickets
- SAN-369 (this entry; sanna-protocol portion -- closes SAN-369)
- Predecessors:
  - sanna-repo SAN-369 portion (Python helper, MERGED at sanna-repo 7e0d3ce)
  - sanna-ts SAN-369 portion (TypeScript helper, MERGED at sanna-ts 60cced0)
- Cross-SDK fixture file in spec/fixtures/receipts/ deferred as a follow-up; AC #4 is met via byte-equal helper parity tests in both SDKs.
- Verifier rejection of MODIFY receipts missing the three fields: SAN-368.

## [Unreleased] -- 2026-05-01 (SAN-361)

### Added
- **Section 14 'AARM Conformance and Mapping'** in `spec/sanna-specification-v1.5.md`. New top-level section documents the public conformance claim (Sanna Protocol v1.5 implements AARM Core (R1-R6) conformance, mechanically verifiable via `sanna-verify aarm`), the Sanna<->AARM R4 decision-enum mapping (5 values), the AARM R5 receipt-field mapping, Manifest framing as GCD Layer 3 (Composition) -- the layer AARM v1.0 does not address, R7/R9 gap acknowledgment (R7 targeted in a future protocol version; R9 is cloud entitlement layer scope), full R6 conformance via `agent_identity` at cv=10, R8 telemetry export framing, and exceedances over AARM v1.0 (operator/agent credential isolation, static composition, hash-chained `parent_receipts`, offline third-party verifiability).
- **v1.5.0 row** in the Version History table summarizing the cv=10 transition.

### Changed
- **Renumbered**: existing Section 14 (Version History) is now Section 15. Single cross-reference updated at the line that referenced Version History.
- **Updated Section 6.8** from forward-pointer skeleton to a brief cross-reference into the new Section 14.

### Tickets
- SAN-361 (this entry)
- Predecessor: SAN-356 G2 (locked the conformance claim text + decision-enum mapping + R5 mapping + Manifest framing + R7/R9 gap + R5/R6 exceedances)
- Unblocks: SAN-368 (AARM-conformance receipt-set verifier `sanna-verify aarm`)
- Cross-references: SAN-204 (cv=10 schema work, MERGED), SAN-370 (cv=10 cascade, MERGED), SAN-371 (CV9_LEGACY warning + migration memo, MERGED)

## [Unreleased] -- 2026-05-01 (SAN-371)

### Added
- `docs/migration/cv9-to-cv10.md`: version-history record for the v1.5 receipt-format transition. Documents what changed (agent_identity at fingerprint position 21), why (AARM R6 binding), how verifiers handle the transition (cv=9 receipts continue to verify with CV9_LEGACY-prefixed warning; cv=10 receipts require agent_identity), and SDK lockstep guidance.

### Compatibility
- **No-action-required for existing signed cv=9 receipts.** Pre-v1.5 receipts remain cryptographically valid; their 20-field fingerprints continue to verify.
- **Verifier CV9_LEGACY warning emission** lands in companion sanna-repo + sanna-ts work under SAN-371.

### Tickets
- SAN-371 (this entry; sanna-protocol portion)
- Predecessor: SAN-370 (cv=10 cascade, MERGED)
- Companions: sanna-repo + sanna-ts verifier CV9_LEGACY warning (separate Opus prompts)

## [Unreleased] -- 2026-05-01 (SAN-389)

### Fixed
- **Artifact self-consistency at v1.5 (SAN-370 Prompt A fallout):** spec submodule's `fixtures/keypairs/test-author.pub`, `fixtures/constitutions/minimal.yaml`, and `fixtures/constitutions/full-featured.yaml` were stale relative to `fixtures/golden-hashes.json` after SAN-370 Prompt A's `generate_fixtures.py` run. Specifically: cv=10 active fixtures were signed with a regenerated keypair (key_id `d28465e3...`) but the new `test-author.{key,pub,meta.json}` files were not committed; bundled keypair retained the pre-SAN-370 key_id `48b9f5ba...`. Constitutions yaml content_hashes diverged from golden-hashes entries.
- **Fix:** generated a fresh keypair on this branch, then re-signed cv=10 active receipt fixtures and `fixtures/constitutions/minimal.yaml` with the new keypair. All non-signature receipt fields (timestamps, enforcement, trust evaluations, fingerprints) preserved byte-identical to the SAN-370 Prompt A state. cv=9 archive fixtures (`fixtures/receipts/archive/v1.4/`) are byte-identical to pre-PR-1 (untouched).

### Compatibility
- **Receipt fingerprints (cv=10) preserved byte-equal:** the 21-field fingerprint formula uses pipe-joined receipt fields, not the signing key. Re-signing with a fresh keypair changes signature values but not fingerprint values. Cross-SDK fingerprint contract validated: `fixtures/receipts/full-featured.json:full_fingerprint = e0794986270598e7ce7e4473cde77c35bd93c4e8fb15b8d1c8328893dd775a0f` (matches sanna-repo + sanna-ts cross-language test target).
- **test_key_id rotates:** `golden-hashes.json:test_key_id` reflects the new bundled keypair (`6edb993...`). Customers/SDK tests that pinned to `d28465e3...` will need to re-pull the spec submodule to get the new key_id.
- **Receipt signatures (Ed25519) for cv=10 fixtures changed:** signatures rotated to the new keypair. All other receipt fields unchanged. cv=9 archive signatures unchanged (different keypair history, archived intact).
- **sanna-ts cross-language test workaround can be reverted:** the `getVerifyKey()` helper in `packages/core/tests/cross-language.test.ts` (added in SAN-370 Prompt C) skipped signature verification on key_id mismatch. Post-SAN-389 with self-consistent keypair, signature verification works strictly. SAN-389 PR-2 (sanna-ts, separate Opus prompt after this PR-1 merges) reverts the workaround.

### Notes
- **Fingerprint instability in generate_fixtures.py (SAN-391 forward-pointer):** running `generate_fixtures.py` from scratch regenerates receipt content with current timestamps. Enforcement, trust-evaluation, and authority-decision objects include `timestamp`/`evaluated_at` fields that are hashed into fingerprint fields 7, 9, and 11 respectively. A full re-run therefore produces different fingerprints, breaking the cross-SDK contract. This PR fixed the artifact gap via targeted re-signing (keypair + signatures only); fingerprint-affecting content was not regenerated. SAN-391 tracks making the generator deterministic.
- **Pre-flight harness (preflight_san389.py) corrected:** the original harness had two bugs discovered during SAN-389 execution: (1) C3 checked archive fixture sig.key_id against the current committed pub -- a coincidence that held pre-regen but breaks post-regen; fixed to check git-diff cleanliness instead. (2) C4/C5 used `load_constitution` + `compute_content_hash` (parsed-object hash, excludes signature) while the generator uses `hash_text(raw_yaml, truncate=64)` -- two incompatible algorithms; fixed to match the generator.

### Tickets
- SAN-389 PR-1 (this entry)
- Predecessor: SAN-370 Prompt A (sanna-protocol 9ee7527, MERGED) -- introduced the artifact divergence
- Successor: SAN-389 PR-2 (sanna-ts, separate prompt) -- reverts cross-language test workaround
- Unblocks: SAN-386 (v1.5 release coordination + customer notification, P1)
- Forward-pointer: SAN-391 (deterministic keypair generation in generate_fixtures.py; auto-regen on every run is non-deterministic)

## [Unreleased] -- 2026-04-30 (SAN-370 Prompt A)

### Changed
- `fixtures/receipts/`: archived 4 active cv=9 fixtures (`escalated.json`, `fail-halted.json`, `full-featured.json`, `pass-single-check.json`) to `fixtures/receipts/archive/v1.4/`. Regenerated active fixtures at cv=10 with `agent_identity` populated per spec Section 2.19. `pass-single-check`, `fail-halted`, `escalated` use the minimum form (just `agent_session_id`); `full-featured` exercises all Section 2.19 sub-fields (`human_principal`, `service_account`, `role`, `privilege_scope`).
- `generate_fixtures.py`: emits cv=10 receipts with the 21-field fingerprint formula and `agent_identity` field. Override of `_EMIT_CHECKS_VERSION` + `_EMIT_SPEC_VERSION` at module level so cv=10 fixtures can be generated even when the installed sanna SDK is still at cv=9 (sanna SDK constants flip in SAN-370 Prompt B).
- `schemas/receipt.schema.json`: `$id` flipped from `https://sanna.dev/schemas/receipt/v1.4.json` to `https://sanna.dev/schemas/receipt/v1.5.json`. Example `checks_version` bumped from `"8"` to `"10"`. Example `spec_version` bumped from `"1.3"` to `"1.5"`. Description reference updated from v1.4.md to v1.5.md. Documenting legacy behavior unchanged.
- `fixtures/golden-hashes.json`: regenerated with cv=10 fingerprints for active fixtures. Top-level metadata reflects spec_version 1.5 + checks_version 10 + fingerprint_fields 21.

### Compatibility
- **Receipt fingerprint compatibility:** post-SAN-370 receipts use the 21-field formula at cv=10 (adds `agent_identity_hash` at field 21 = `hash_obj(agent_identity)`). cv=9 legacy receipts continue to validate via the 20-field formula; verifiers dispatch on `checks_version`. Existing signed cv=9 receipts remain valid (signature is over what was emitted; their 20-field fingerprint formula is preserved). Re-emission of the same input post-upgrade produces a different fingerprint (cv=10 includes `agent_identity_hash`; cv=9 didn't have field 21 at all).
- **SDK lockstep:** sanna-repo (Python) and sanna-ts (TypeScript) flip `SPEC_VERSION` 1.4 -> 1.5 and `CHECKS_VERSION` 9 -> 10 in SAN-370 Prompts B + C. Until those merge, the SDKs continue emitting cv=9 receipts; the active cv=10 fixtures in this PR are generation-time only (consumed by post-Prompt-B/C SDK tests once submodule pins bump).
- **Schema $id flip is a metadata change.** Verifiers + tooling that reference the schema by URL should update if they had hardcoded the v1.4.json path (none known; sanna-protocol is the publisher).
- **Library middleware MAY emit cv=9** post-SAN-370. Per spec Section 2.19 line 781-782, library middleware (non-gateway, non-interceptor) MAY emit at the lower checks_version. Gateway and interceptors emit cv=10 with agent_identity. SDK call-site discipline (Issue Y design lock) lands in Prompt B + C.

### Tickets
- SAN-370 Prompt A (this entry)
- Companion: SAN-370 Prompt B (sanna-repo SDK constants flip + agent_identity emission + cv-dispatch fingerprint, blocked on this), SAN-370 Prompt C (sanna-ts mirror, blocked on Prompt B).
- Spec/schema/fingerprint formula doc: SAN-204 (MERGED at sanna-protocol c1ae331).
- Out-of-scope follow-ups: SAN-368 (AARM-conformance verifier), SAN-369 (MODIFY parameter recording), SAN-371 (cv=10 cascade legacy warnings + customer notification), SAN-384 (cv<10 -> agent_identity-absent negative schema rule, Backlog).

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
