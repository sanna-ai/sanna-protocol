# Versioning

How the Sanna Protocol and its reference SDKs are versioned, bumped, and kept in lockstep. This document is normative for Sanna maintainers and informative for third-party SDK implementers.

## Current state (as of 2026-04-20)

| Layer | Version |
|---|---|
| Protocol `SPEC_VERSION` | `1.4` |
| Protocol `CHECKS_VERSION` | `9` |
| Python SDK (`sanna`) | `1.4.0` (pending v1.4-B merge) |
| TypeScript SDK (`@sanna-ai/core`) | `1.4.0` (pending v1.4-C merge) |
| Skipped versions | `1.2` (spec doc-only; never shipped in SDK) |

Last protocol release: SAN-222, protocol-only v1.4-A, 2026-04-20. SDK releases (v1.4-B Python, v1.4-C TypeScript) follow after SDK implementations are complete and round-trip validated against the new protocol goldens.

Last coordinated full release: Sprint 15, SAN-211 / SAN-213 / SAN-214 / SAN-216, landed across all three repos 2026-04-18 → 2026-04-19.

## v1.4 release (2026-04-20)

Two new governance-relevant additions:

1. **`tool_name` field (required at cv>=9).** Separates SDK identity from
   SDK version. `tool_version` stays bare semver; `tool_name` is a
   registered enum (`"sanna"`, `"sanna-ts"`). Future third-party SDKs
   register values via spec PR. Rationale: avoid overloading `tool_version`
   with identity+version (v1.3 had this coupling).

2. **Agent-model fields (optional, nullable).** New fields `agent_model`,
   `agent_model_provider`, `agent_model_version` capture which LLM model
   the agent was running on when the receipt was generated. Opt-out via
   null (absent-vs-null is normatively distinct per Section 2.18.4 of the
   spec). Fingerprint extends to 20 fields; all four new fields participate
   at cv=9.

Fingerprint formula: cv=9 uses 20 pipe-delimited fields. Positions 17-20
are `tool_name_hash`, `agent_model_hash`, `agent_model_provider_hash`,
`agent_model_version_hash`. Legacy dispatch unchanged (cv=8 → 16,
cv=6/7 → 14, cv≤5 → 12).

SDK package versions bump coordinated: Python sanna `1.3.0` → `1.4.0`; TS
all four packages bump to `1.4.0` (closing the SAN-217-flagged version lag
where `@sanna-ai/core` was at `1.1.1`). No version skip.

## Scope

Three independently versioned artifacts:

1. **Protocol** — `sanna-protocol` repo. Defines receipt shape, constitution shape, fingerprint formula, and normative verifier behavior. Versioned by `SPEC_VERSION` (semantic, e.g. `"1.3"`) and `CHECKS_VERSION` (monotonic integer, e.g. `"8"`).
2. **Python SDK** — `sanna-repo` repo, published to PyPI as `sanna`. Versioned by PyPI semver (`1.3.0`).
3. **TypeScript SDK** — `sanna-ts` repo, published to npm as `@sanna-ai/core` (and sibling packages). Versioned by npm semver (`1.3.0`).

This document governs how bumps across these three layers stay coherent.

## Version layers

### `SPEC_VERSION`

Semantic version of the protocol itself. Appears in every receipt as `spec_version`. Controls:

- Required fields at the receipt's protocol level
- Normative rules verifiers MUST enforce
- JSON Schema `$id` for the receipt schema (e.g. `receipt/v1.3.json`)

Bumps are rare and always coordinated with SDK releases. See "Coordinated bumps" below.

### `CHECKS_VERSION`

Monotonic integer tracking the fingerprint formula. Appears in every receipt as `checks_version`. Controls:

- Field count in the fingerprint formula (12 at `cv="5"`, 14 at `cv="6"`/`"7"`, 16 at `cv="8"`, 20 at `cv="9"`)
- Field ordering in the fingerprint string
- Which hashes participate in the fingerprint

Every `CHECKS_VERSION` bump produces receipts whose fingerprint bytes differ from the prior version, even for identical inputs. Verifiers MUST dispatch on `checks_version` to select the correct formula.

### SDK package version

Standard semver (`MAJOR.MINOR.PATCH`) for the installable package. Controls:

- Installable API surface
- Code-level behavior for receipt construction, verification, middleware, gateway, interceptors

SDK package versions follow the protocol versions they implement, but can tick independently for bug fixes that don't change receipt wire format.

### How the three relate

| Change class | `SPEC_VERSION` | `CHECKS_VERSION` | SDK package |
|---|---|---|---|
| New required receipt field at protocol level | Bump | Bump (if participates in fingerprint) | Minor bump |
| Fingerprint formula change (field added/reordered) | Bump | Bump | Minor bump |
| New verifier normative rule | Bump | — | Minor bump |
| Error-message upgrade; no wire-format change | — | — | Patch |
| Security fix; no wire-format change | — | — | Patch |
| New SDK public API; backward-compatible | — | — | Minor bump |
| Breaking SDK API change | — | — | Major bump |
| Breaking receipt/constitution structural change | Major bump | Bump | Major bump |

Rule: **fingerprint-affecting changes are never patch-level** in any layer. They change the bytes of produced receipts, which third parties pattern-match on.

## Coordinated bumps

`SPEC_VERSION` and SDK versions ship together. No exceptions.

A protocol spec advertising behavior that the reference SDKs do not implement is worse than a spec advertising less than the SDKs do — third-party implementers will build to the spec, then interop with the SDKs will fail. The spec is the contract; the SDKs are the proof the contract is honored.

### Required ordering in a coordinated release

1. Draft protocol PR with new spec language, schema changes, and golden fixtures
2. Draft Python SDK PR implementing the new protocol behavior
3. Draft TS SDK PR implementing the new protocol behavior (submodule-pinned to the protocol PR branch if needed)
4. Run cross-repo validation: Python SDK PR against updated protocol goldens; TS SDK PR against same goldens; fingerprints must match byte-for-byte
5. Merge protocol PR first (canonical source of truth)
6. Merge SDK PRs with the submodule pointer pointing at the now-merged protocol commit
7. Cut PyPI and npm releases from the merged SDK commits

Deviations (e.g., one SDK lands later than the other) are acceptable only if the drift window is explicitly documented in the lagging SDK's CHANGELOG with a commitment to close the gap by a named sprint.

## Round-trip validation (Gate 2 governance flag)

Any spec claim describing SDK behavior MUST be validated against SDK goldens before the spec merges.

### The rule

If the spec asserts "the SDK does X", the SDK must actually do X, verified by running the SDK's test suite against the golden fixtures referenced by the spec. If the tests fail, one of two things:

- **Fix the SDK** — bring behavior in line with the spec claim
- **Narrow the spec** — restrict the claim to what the code actually does

Never publish a spec with an untested behavioral claim. Third-party implementers will build to it.

### The incident that motivated this rule

Sanna v0.13.2 shipped a spec that said "NFC normalization applies to all strings." The code only normalized at the `hash_text()` boundary. Third-party implementers who applied NFC universally produced different fingerprints than the Python reference. The spec was narrowed in a follow-up patch; the incident became a governance flag.

### Practical implementation

- Protocol PRs adding normative SDK behavior claims must include: the spec text, the corresponding SDK golden fixture diff, and evidence (CI green or local test output) that the SDK produces the claimed output on that fixture
- Reviewers look for "is there a test that proves the code does what the spec says" — if no, reject the PR

## Skip-version handling

Occasionally a protocol version gets drafted but never ships in any SDK release. The spec doc may exist; the schema may reference the version; the SDKs never emit it. That's a "skipped version."

### Rule

When the next shipped SDK arrives after a skipped spec version, SDK package numbering MUST skip the unshipped version.

Example: `v1.2` was drafted for sanna-protocol (spec doc + schema `$id`) but no Python or TS SDK ever emitted `spec_version="1.2"`. Sprint 15 shipped `v1.3`. The Python SDK package jumped `1.1.0 → 1.3.0`, skipping `1.2.0`.

### Normative statement for verifiers

**A receipt claiming a skipped `spec_version` is spurious.** No SDK ever produced such a receipt. Its existence in the wild implies hand-rolled fake content, tool misconfiguration, or deliberate tampering. Verifiers MUST either reject these receipts or emit a loud warning.

Current skipped versions: `1.2`.

### Documentation requirements when declaring a skipped version

- Spec version history table (in `sanna-specification-v{next}.md`) marks the version as "doc-only; skipped in SDK"
- `sanna-protocol/CHANGELOG.md` includes a normative statement naming the skipped version and declaring spurious-receipt status
- Both SDK CHANGELOGs explain the jumped package number (e.g., "`1.1.0` → `1.3.0`; `1.2.0` skipped per spec skip")

## Dict-mutation pattern (Option B lesson)

Receipts are constructed by `generate_receipt()` (Python) and `generateReceipt()` (TypeScript). When a caller has an enforcement outcome to record, the enforcement object MUST be passed as a kwarg at construction time:

```python
# Python — correct (Option B, structural enforcement)
receipt = generate_receipt(
    trace_data,
    enforcement=my_enforcement,   # applies cross-field override at build
    ...
)
```

```typescript
// TypeScript — correct
const receipt = generateReceipt({
  correlation_id: "...",
  // ...
  enforcement: myEnforcement,
});
```

### What NOT to do

Never mutate `receipt.enforcement` (or any enforcement-adjacent field) after construction:

```python
# Python — WRONG (Option A, caller discipline; bypasses override)
receipt = generate_receipt(trace_data, ...)    # no enforcement passed
receipt.enforcement = my_enforcement            # mutation after construction
# receipt.status is now inconsistent with receipt.enforcement.action
```

### Why

The `enforcement` → `status` override fires at receipt construction time. It enforces the Sanna v1.3 Section 4.6 cross-field consistency rule: a receipt with `enforcement.action="halted"` and `status="PASS"` would misrepresent what governance did. The override catches this.

Post-hoc mutation of `receipt.enforcement` does not trigger the override. The mutation can produce a receipt whose `status` field contradicts its `enforcement.action` field — cryptographically valid, semantically defective. The reference verifier (since SAN-214) catches this at verify time, so damage is contained, but construction time is the correct place to prevent it.

### Normative for third-party SDK implementers

Any SDK implementing a `generate_receipt` equivalent:

- MUST apply the enforcement override structurally at construction (Option B)
- MUST NOT rely on caller discipline to set `status` correctly (Option A)
- SHOULD also reject post-hoc mutation if the SDK's type system allows (e.g., immutable receipt types in languages that support them)

The override mapping is:

| `enforcement.action` | Override fires when computed status is | Final status |
|---|---|---|
| `halted` | `PASS` | `FAIL` |
| `warned` | `PASS` | `WARN` |
| `escalated` | `PASS` | `WARN` |
| `allowed` | (never overrides) | `PASS` |

When computed status is already `WARN`, `FAIL`, or `PARTIAL`, the override does not fire (the receipt already reflects a non-pass outcome). This is intentional: the verifier's cross-field consistency check catches the edge case where severity-WARN checks coexist with `enforcement.action="halted"`, providing belt-and-suspenders coverage.

### The incident that motivated this rule

Sprint 15, SAN-213 Branch 2. Python interceptor receipts were emitting `status="PASS"` with `enforcement.action="halted"` because the caller-discipline approach (Option A) failed in practice — every emit site had to remember to set status correctly, and not every emit site did. The fix (Branch 2B) moved the override into `generate_receipt()` itself. Branch 2C added the `escalated` case. SAN-214 added the verifier-side override as belt-and-suspenders.

## Version-bump checklist

Before merging any PR that bumps `SPEC_VERSION` or `CHECKS_VERSION`:

- [ ] Classified the bump correctly per the Version layers table above
- [ ] Identified all repos affected (protocol + Python SDK + TS SDK)
- [ ] Drafted PRs in each affected repo on coordinated branches
- [ ] Ran round-trip validation: each SDK produces byte-identical receipts for the canonical inputs defined in the new protocol goldens
- [ ] Updated `CHANGELOG.md` in every affected repo
- [ ] Updated the version history table in `sanna-specification-v{next}.md`
- [ ] If skipping a version: added normative spurious-receipt statement to spec + CHANGELOG
- [ ] Regenerated golden fixtures where the fingerprint formula changed; archived old goldens with version tag
- [ ] Verified all SDK test assertions referencing version literals are updated
- [ ] Schema `$id` in `sanna-protocol/schemas/receipt.schema.json` (and sync'd copies in SDK repos) reflects the new version
- [ ] Both SDK `tool_version` defaults updated (e.g., `sanna-ts/1.3.0`, `sanna/1.3.0`)
- [ ] Coordinated merge order planned: protocol first, SDKs after with updated submodule pointers (if the SDK uses a submodule)

For SDK-only bumps (patch/minor, no protocol change):

- [ ] Confirmed receipt wire format is unchanged
- [ ] CHANGELOG explains what changed at the SDK level
- [ ] If bug fix, linked to the incident/ticket that motivated it

## References

- `spec/sanna-specification-v1.4.md` — current normative spec
- `schemas/receipt.schema.json` — current receipt schema
- `schemas/constitution.schema.json` — current constitution schema
- `CHANGELOG.md` — version history for the protocol
- SDK-side CHANGELOGs: `sanna-repo/CHANGELOG.md`, `sanna-ts/CHANGELOG.md`
