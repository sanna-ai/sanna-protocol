# Sanna Protocol — Architecture

Formal specification for the Sanna Protocol — receipt format, canonicalization
rules, Ed25519 signing, fingerprint construction, and verification steps. This
is the **source of truth** that all SDK implementations (Python `sanna`,
TypeScript `@sanna/core`) build against.

Sanna is "Trust Infrastructure for AI agents" built on two **co-equal** pillars:
- **Constitution enforcement** — constraining AI agent behavior via cryptographically signed YAML constitutions
- **Reasoning receipts** — tamper-evident, cryptographically signed records proving governance was enforced

Never present one pillar as subordinate to the other.

---

## Current Version

- **Spec version:** 1.4 (`spec/sanna-specification-v1.4.md`)
- **checks_version:** `"9"` (current default at v1.4+)
- **Schema:** `schemas/receipt.schema.json` (JSON Schema 2020-12)

See `docs/state.md` for auto-generated version snapshot (spec version,
checks_version, schema list, fixture count).

---

## Key Files

| Path | Purpose |
|------|---------|
| `spec/sanna-specification-v1.4.md` | The specification (source of truth) |
| `schemas/receipt.schema.json` | Receipt JSON Schema |
| `schemas/constitution.schema.json` | Constitution JSON Schema |
| `fixtures/` | Golden test fixtures (keypairs, receipts, constitutions, hashes) |
| `fixtures/canonicalization-vectors.json` | Cross-language canonicalization test vectors |
| `fixtures/authority-matching-vectors.json` | Cross-SDK authority matching contract (21 vectors) |
| `fixtures/multi-surface-vectors.json` | CLI/API multi-surface test vectors |
| `generate_fixtures.py` | Regenerates golden receipts (requires `pip install sanna`) |
| `generate_test_vectors.py` | Generates canonicalization test vectors (requires `hypothesis`) |
| `docs/implementers-guide.md` | Cross-language implementation guide |

---

## Fingerprint Formula — cv-dispatch ladder

Verifiers dispatch on `checks_version` (as an integer) to select the correct
field count. The fingerprint input is a pipe-delimited string of exactly N fields,
passed to SHA-256.

### Version history

| checks_version | Protocol version | Field count | Change |
|---|---|---|---|
| `"5"` | v1.0.x | **12 fields** (legacy) | Initial formula |
| `"6"` | v1.1.0 | **14 fields** | Added `parent_receipts_hash` (field 13), `workflow_id_hash` (field 14) |
| `"7"` | SDK-internal (post-v1.0.0) | **14 fields** | Empty-checks fingerprint normalization; uses same 14-field formula as cv=6 |
| `"8"` | v1.3.0 | **16 fields** | Added `enforcement_surface_hash` (field 15), `invariants_scope_hash` (field 16) |
| `"9"` | v1.4.0 | **20 fields** | Added `tool_name_hash` (field 17), `agent_model_hash` (field 18), `agent_model_provider_hash` (field 19), `agent_model_version_hash` (field 20) |

Dispatch rule: `"9"` or higher → 20 fields; `"8"` → 16 fields; `"6"` or `"7"` → 14 fields; `"5"` → 12 fields.

### 20-field formula (cv=9, v1.4+) — current

```
correlation_id | context_hash | output_hash | checks_version |
checks_hash | constitution_hash | enforcement_hash | coverage_hash |
authority_hash | escalation_hash | trust_hash | extensions_hash |
parent_receipts_hash | workflow_id_hash |
enforcement_surface_hash | invariants_scope_hash |
tool_name_hash | agent_model_hash |
agent_model_provider_hash | agent_model_version_hash
```

- Fields 1 and 4 are literal strings; all others are 64-hex SHA-256 or EMPTY_HASH
- Field 17: `tool_name_hash = hash_text(tool_name)`. REQUIRED at cv≥9; EMPTY_HASH indicates malformed receipt.
- Field 18: `agent_model_hash = hash_text(agent_model)`, or EMPTY_HASH if null or absent.
- Field 19: `agent_model_provider_hash = hash_text(agent_model_provider)`, or EMPTY_HASH if null or absent.
- Field 20: `agent_model_version_hash = hash_text(agent_model_version)`, or EMPTY_HASH if null or absent.
- For fields 18-20: both `null` and absent produce EMPTY_HASH — the fingerprint does not distinguish opt-out from not-captured.

### 16-field formula (cv=8, v1.3) — legacy support

```
correlation_id | context_hash | output_hash | checks_version |
checks_hash | constitution_hash | enforcement_hash | coverage_hash |
authority_hash | escalation_hash | trust_hash | extensions_hash |
parent_receipts_hash | workflow_id_hash |
enforcement_surface_hash | invariants_scope_hash
```

- Fields 15-16 (added in v1.3, SAN-213): `enforcement_surface_hash = hash_text(enforcement_surface)`, `invariants_scope_hash = hash_text(invariants_scope)`.
- `enforcement_surface ∈ {middleware, gateway, cli_interceptor, http_interceptor}`
- `invariants_scope ∈ {full, authority_only, limited, none}`
- Still load-bearing: any cv=8 receipt verified by current SDKs uses this formula.

### 14-field formula (cv=6/7) — legacy support

Fields 1-14: same as 16-field, minus `enforcement_surface_hash` and `invariants_scope_hash`.

### 12-field formula (cv=5) — legacy support

Fields 1-12: same as 14-field, minus `parent_receipts_hash` (field 13) and `workflow_id_hash` (field 14).

### EMPTY_HASH sentinel

`EMPTY_HASH = sha256_hex(b"") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

Fields not present in a given formula (e.g., `enforcement_surface` in a cv=5 receipt) are simply not included — they do not contribute EMPTY_HASH; they are absent from the pipe-delimited string entirely.

---

## Principles

- The protocol spec is the source of truth. Don't add fields to SDKs without protocol backing.
- Correctness over convenience. No audit gaps.
- The protocol must be fully specified so third-party implementations can implement it without reading SDK source.
- Verifiers MUST dispatch on `checks_version` (as integer) to select the correct field count.

---

## Cross-SDK byte-parity invariant

The protocol's load-bearing claim is that a Sanna receipt means the same thing
everywhere. Python (`sanna`) and TypeScript (`@sanna/core`) MUST produce byte-
identical fingerprints for identical inputs. The canonicalization test vectors
(`fixtures/canonicalization-vectors.json`) and authority-matching vectors
(`fixtures/authority-matching-vectors.json`) are the normative cross-SDK
contract. Both SDKs MUST pass all vectors before a protocol version ships.

Any divergence between SDK outputs is a protocol bug, not an SDK bug. File
against `sanna-protocol` and block the release.

---

## Working With This Repo

**Editing the spec:** Edit `spec/sanna-specification-v1.4.md` directly. Keep
RFC 2119 language (`MUST`, `MUST NOT`, `SHOULD`, etc.).

**Schema changes:** Must be reflected in both the spec and
`schemas/receipt.schema.json`. Schema and spec are co-required; never ship
a new spec field without a corresponding schema entry (or vice versa).

**Regenerating fixtures:**
```bash
python3 generate_fixtures.py
```
Generates a fresh keypair each run, so `receipt_id`/timestamps/signatures
change but the fingerprint algorithm is deterministic.

**Regenerating canonicalization test vectors:**
```bash
python3 generate_test_vectors.py
```
Outputs `fixtures/canonicalization-vectors.json`.

**Regenerating state doc:**
```bash
python3 tools/generate_state_doc.py
```
Outputs `docs/state.md`. Run after any change that affects spec version,
checks_version, schemas, or fixture count. CI gate runs `--check` on every PR.

**Verification reference:** The installed `sanna` CLI may lag behind spec
changes. Use the verification logic in `generate_fixtures.py`
(`recompute_fingerprint`) as the reference implementation.

---

## Commit and versioning conventions

- Protocol version changes get tagged (e.g., `v1.4`)
- Spec patches use semver: `1.4.1` for clarifications, `1.5.0` for new fields, `2.0.0` for breaking changes
- See `VERSIONING.md` for the full versioning discipline (coordinated bumps, round-trip validation / Gate 2, skip-version handling, dict-mutation / Option B pattern)
- See `CHANGELOG.md` for protocol version history

---

## Architectural decisions

Architectural decisions are recorded in `docs/decisions/` (ADR bootstrap
forthcoming in a follow-up PR per SAN-326 sequencing). Until that directory
exists, rationale for major design choices (fingerprint formula, authority
matching semantics, NFC scope, etc.) can be found in the commit messages and
CHANGELOG entries for the relevant protocol versions.
