# Implementers Guide

This guide is for developers building a Sanna Protocol-conformant SDK in any
language. It covers the critical implementation details that must be exact for
cross-language interoperability.

---

## 1. Start with the Golden Fixtures

Before writing any code, familiarize yourself with the test fixtures in
`fixtures/`. These are your ground truth. A conformant implementation must
produce identical hashes and fingerprints for the same inputs.

```
fixtures/
├── keypairs/          # Ed25519 test keypair (PEM format)
├── constitutions/     # Signed constitutions (YAML + .sig)
├── receipts/          # 4 receipt variants (JSON)
└── golden-hashes.json # Expected hashes for all fixtures
```

See `fixtures/README.md` for detailed usage instructions.

---

## 2. Canonicalization (Get This Right First)

All hash computations depend on Sanna Canonical JSON. If your canonicalization
diverges from the reference, every hash will be wrong.

**Rules:**

1. Sort object keys by byte-wise comparison of UTF-8 encoded keys
2. No whitespace: separators are `,` and `:` (no spaces)
3. `ensure_ascii=False` — non-ASCII characters appear as literal UTF-8
4. No HTML escaping — `<`, `>`, `&` are literal, not `\u003c`, `\u003e`, `\u0026`
5. NFC Unicode normalization applied at the hashing boundary

**Language-specific notes:**

| Language | Canonicalization approach |
|----------|-------------------------|
| Python | `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` |
| TypeScript/JavaScript | Use the `canonicalize` npm package or hand-roll with `JSON.stringify` replacer |
| Go | Custom encoder with `SetEscapeHTML(false)` — the default `encoding/json` HTML-escapes `<>& ` |
| Rust | `serde_json` with `to_string` (satisfies requirements by default) |

**Verification test:**

```
canonicalize({"b": 2, "a": 1}) → '{"a":1,"b":2}'
```

Compare your output against `golden-hashes.json` for all fixture inputs.

---

## 3. Hashing

### hash_text(s)

1. NFC normalize the string (Unicode UAX #15)
2. Normalize line endings: `\r\n` and `\r` → `\n`
3. Strip trailing whitespace from each line
4. Strip leading and trailing whitespace from the entire string
5. Encode as UTF-8 bytes
6. SHA-256 hash
7. Return lowercase hex (64 characters by default, or truncated to N)

### hash_obj(obj)

1. Canonical JSON serialize the object
2. Pass the resulting string to `hash_text()`

### EMPTY_HASH

The SHA-256 of zero bytes. Used as sentinel for absent fields in fingerprint
computation.

```
EMPTY_HASH = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

## 4. Fingerprint Construction

The fingerprint is a pipe-delimited string of 12 components, hashed with
SHA-256. This is the tamper-evidence mechanism — get it wrong and no receipt
will verify.

```
fingerprint_input = "{correlation_id}|{context_hash}|{output_hash}|{checks_version}|{checks_hash}|{constitution_hash}|{enforcement_hash}|{coverage_hash}|{authority_hash}|{escalation_hash}|{trust_hash}|{extensions_hash}"
```

**Rules:**

- Always exactly 12 pipe-separated fields
- `correlation_id` and `checks_version` are literal string values
- All other components are 64-char hex SHA-256 or `EMPTY_HASH`
- Absent optional fields → `EMPTY_HASH` (null and missing are identical)
- Strip `constitution_approval` from `constitution_ref` before hashing
- `receipt_fingerprint` = first 16 chars of `hash_text(fingerprint_input)`
- `full_fingerprint` = full 64 chars of `hash_text(fingerprint_input)`

### Checks Hash

Hash each check as a dict with a specific field set:

- **Without constitution:** `check_id`, `passed`, `severity`, `evidence`
- **With constitution:** add `triggered_by`, `enforcement_level`, `check_impl`, `replayable`

Hash checks in insertion order (do NOT sort). Null fields must be included
as JSON `null` (not omitted).

---

## 5. Cryptographic Signing

### Algorithm

Pure Ed25519 (RFC 8032). No context string, no pre-hashing.

- Signatures: 64 bytes (R ‖ S)
- Base64: RFC 4648 standard with padding (`+`, `/`, `=`)
- Base64url MUST be rejected

### Key Format

- Private keys: PKCS#8 PEM (unencrypted)
- Public keys: SubjectPublicKeyInfo PEM
- Key ID: SHA-256 of the raw 32-byte Ed25519 public key (not DER)

### Receipt Signing Steps

1. Create `receipt_signature` block with `signature: ""`
2. Attach to a copy of the receipt
3. Run `sanitize_for_signing()` — convert exact-integer floats to integers,
   reject non-integer floats, NaN, Infinity
4. Serialize with canonical JSON
5. Sign the bytes with Ed25519 private key
6. Base64-encode the 64-byte signature
7. Replace the empty placeholder with the actual signature

---

## 6. Constitution Loading

Constitutions are YAML documents validated against `schemas/constitution.schema.json`.

**Required sections:** `identity`, `provenance`, `boundaries`

**Validation steps:**

1. Parse YAML
2. Validate against JSON Schema (draft 2020-12)
3. Compute `policy_hash` = `hash_obj(constitution_content)`
4. If signed, verify Ed25519 signature over raw YAML bytes

---

## 7. Authority Evaluation

The authority evaluator determines whether an agent can execute, must
escalate, or cannot execute a given tool call.

**Policy cascade (order matters):**

1. Per-tool override (exact match on original tool name)
2. Server default policy
3. Constitution authority boundaries (with name normalization)
4. No match → `cannot_execute` (fail closed)

**Name normalization for boundary matching:**

1. NFKC normalize
2. Split camelCase at case transitions
3. Split on separators (`_-./:\@`)
4. Casefold all tokens
5. Join with `.`

See Appendix D of the specification for the full algorithm and test vectors.

---

## 8. Verification Pipeline

Implement these checks in order:

| Step | Check | Exit Code |
|------|-------|-----------|
| 1 | JSON schema validation | 2 |
| 2 | Content hash recomputation | 3 |
| 3 | Fingerprint recomputation | 3 |
| 4 | Status consistency | 4 |
| 5 | Check count consistency | 4 |
| 6 | Receipt signature (if public key available) | 5 |

Return the highest-priority exit code encountered.

---

## 9. Cross-Language Testing Strategy

1. Load the test keypair from `fixtures/keypairs/`
2. Load each fixture receipt from `fixtures/receipts/`
3. Recompute `context_hash` and `output_hash` from inputs/outputs
4. Recompute the fingerprint from receipt fields
5. Compare all computed values against `fixtures/golden-hashes.json`
6. Verify Ed25519 signatures using the test public key
7. Optionally: generate a receipt in your language, verify with the Python CLI

If all golden hashes match, your implementation is conformant.

---

## 10. Common Pitfalls

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| HTML escaping in JSON | Hashes don't match (Go, Java) | Disable HTML escaping in JSON encoder |
| Floats in signed fields | Signature verification fails | Sanitize: convert `1.0` → `1`, reject `3.14` |
| Missing NFC normalization | Hash mismatch on non-ASCII inputs | Apply NFC at the hashing boundary |
| Sorting checks before hashing | checks_hash mismatch | Hash in insertion order, never sort |
| Omitting null fields in checks hash | checks_hash mismatch | Include `"field": null` in canonical JSON |
| Using Base64url | Signature rejection | Use standard Base64 with padding |
| Key ID from DER bytes | Key ID mismatch | Hash the raw 32-byte public key, not DER |
| Wrong line endings | hash_text mismatch | Normalize `\r\n` and `\r` to `\n` |
| constitution_approval in fingerprint | Fingerprint mismatch | Strip before computing constitution_hash |

---

## 11. Reference Implementations

| Language | Package | Status |
|----------|---------|--------|
| Python | [`sanna`](https://pypi.org/project/sanna/) | Released (v0.13.5+) |
| TypeScript | `@sanna/core` | Coming soon |
