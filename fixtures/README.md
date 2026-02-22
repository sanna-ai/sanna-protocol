# Golden Test Fixtures

These fixtures are the canonical test vectors for the Sanna Protocol. Any
conformant implementation must produce identical hashes and fingerprints
for the same inputs, and must successfully verify all signed artifacts.

## Contents

```
fixtures/
├── keypairs/
│   ├── test-author.key          # Ed25519 private key (PKCS#8 PEM) — TEST USE ONLY
│   ├── test-author.pub          # Ed25519 public key (SubjectPublicKeyInfo PEM)
│   └── test-author.meta.json    # Key metadata (label, key_id)
├── constitutions/
│   ├── minimal.yaml             # Simplest valid constitution (signed)
│   └── full-featured.yaml       # All schema sections exercised
├── receipts/
│   ├── pass-single-check.json   # All checks pass, status PASS
│   ├── fail-halted.json         # Critical failure, enforcement halted
│   ├── escalated.json           # must_escalate enforcement action
│   └── full-featured.json       # All optional fields populated
└── golden-hashes.json           # Expected hashes for all fixtures
```

## How to Use These Fixtures

### Step 1: Load the test keypair

Load `keypairs/test-author.key` and `keypairs/test-author.pub` using your
Ed25519 implementation. The key ID (SHA-256 of the raw 32-byte public key)
must match the `test_key_id` in `golden-hashes.json`.

### Step 2: Verify each receipt

For each receipt in `receipts/`:

1. **Parse** the JSON and validate against `schemas/receipt.schema.json`
2. **Recompute `context_hash`** from `inputs` using Sanna Canonical JSON + SHA-256
3. **Recompute `output_hash`** from `outputs` using Sanna Canonical JSON + SHA-256
4. **Recompute the fingerprint** using the 12-field pipe-delimited formula
5. **Compare** all computed values against `golden-hashes.json`
6. **Verify the Ed25519 signature** using the test public key

### Step 3: Verify the constitution

1. **Parse** `constitutions/minimal.yaml` and validate against `schemas/constitution.schema.json`
2. **Verify the embedded signature** using the test public key
3. **Compute the content hash** and compare against `golden-hashes.json`

## Receipt Variants

| Fixture | Status | Enforcement | Description |
|---------|--------|-------------|-------------|
| `pass-single-check.json` | PASS | None | Simple passing receipt — all 5 checks pass |
| `fail-halted.json` | FAIL | halted | Critical check failure triggers enforcement halt |
| `escalated.json` | PASS | escalated | Checks pass but action requires human approval |
| `full-featured.json` | PASS | allowed | All optional fields populated: constitution_ref, enforcement, evaluation_coverage, authority_decisions, source_trust_evaluations, extensions |

## golden-hashes.json

This file contains the expected values for cross-language verification:

```json
{
  "generated_with": "sanna v0.13.5",
  "spec_version": "1.0",
  "checks_version": "5",
  "EMPTY_HASH": "e3b0c44...",
  "test_key_id": "c7a4db8...",
  "receipts": {
    "pass-single-check": {
      "receipt_id": "...",
      "correlation_id": "sanna-fixture-pass-001",
      "context_hash": "...",
      "output_hash": "...",
      "receipt_fingerprint": "...",
      "full_fingerprint": "...",
      "status": "PASS",
      "checks_passed": 5,
      "checks_failed": 0,
      "signature_key_id": "...",
      "signature_scheme": "receipt_sig_v1",
      "canonical_json_sha256": "..."
    }
  },
  "constitutions": {
    "minimal": { "content_hash": "..." },
    "full-featured": { "content_hash": "..." }
  }
}
```

**Fields to verify:**

| Field | What to check |
|-------|---------------|
| `context_hash` | Recompute from `inputs` via `hash_obj()` |
| `output_hash` | Recompute from `outputs` via `hash_obj()` |
| `receipt_fingerprint` | Recompute via 12-field formula, take first 16 hex chars |
| `full_fingerprint` | Recompute via 12-field formula, full 64 hex chars |
| `signature_key_id` | Must match `test_key_id` |
| `canonical_json_sha256` | SHA-256 of canonical JSON of receipt (without signature block) |

## Regenerating Fixtures

The fixtures were generated with the Python reference implementation using
`generate_fixtures.py` in the repo root:

```bash
pip install sanna
python generate_fixtures.py
```

This generates a fresh keypair on each run, so receipt_id, timestamps, and
signatures will change. The content hashes and fingerprint algorithms remain
deterministic for the same inputs.

## Security Note

The private key (`test-author.key`) is included for **testing purposes only**.
It allows implementers to verify signing and key-loading code. Never use test
keys in production.
