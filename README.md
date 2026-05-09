# Sanna Protocol

Open specification for cryptographic governance receipts. When an AI agent acts, the Sanna Protocol evaluates the action against a constitution, enforces boundaries, and produces a signed receipt proving governance was applied. The receipt binds the policy document, the evaluation result, and the enforcement outcome into a single tamper-evident artifact using Ed25519 signatures and RFC 8785 JSON canonicalization.

## Repository Contents

| Path | Description |
|------|-------------|
| [`spec/`](spec/sanna-specification-v1.4.md) | Protocol specification v1.4 — receipt format, 20-field fingerprint (cv=9), tool identity, agent-model audit fields, multi-surface governance, canonicalization, signing, verification |
| [`schemas/`](schemas/) | JSON Schema (2020-12) for [constitutions](schemas/constitution.schema.json) and [receipts](schemas/receipt.schema.json) |
| [`fixtures/`](fixtures/) | Golden test fixtures — test keypair, signed constitutions, 4 receipt variants, expected hashes, 1,296 canonicalization test vectors, 24 multi-surface (CLI/API) test vectors |
| [`templates/`](templates/) | Starter constitutions: [privacy-focused](templates/privacy-focused.yaml), [developer](templates/developer.yaml), [locked-down](templates/locked-down.yaml) |
| [`http/`](http/header-conventions.md) | HTTP header conventions (`X-Sanna-Receipt`, `X-Sanna-Receipt-URL`, `X-Sanna-Verify`, `X-Sanna-Constitution`) |
| [`docs/`](docs/) | [Implementers guide](docs/implementers-guide.md), [protocol comparison](docs/protocol-comparison.md) (Sanna vs ORS v0.1) |

## Implementations

| Language | Package | Install |
|----------|---------|---------|
| Python | [`sanna`](https://pypi.org/project/sanna/) | `pip install sanna` |
| TypeScript | [`@sanna-ai/core`](https://www.npmjs.com/package/@sanna-ai/core) | `npm install @sanna-ai/core` |

## Conformance Verification

A conformant implementation must produce identical hashes and fingerprints for identical inputs. The [`fixtures/`](fixtures/) directory contains everything needed to verify:

1. Load the test keypair from `fixtures/keypairs/`
2. For each receipt in `fixtures/receipts/`, recompute `context_hash`, `output_hash`, and the cv-appropriate fingerprint (20-field at cv=9, 16-field at cv=8, 14-field at cv=6/7, 12-field at cv=5)
3. Compare all computed values against `fixtures/golden-hashes.json`
4. Verify Ed25519 signatures using the test public key

All hashes match → conformant. See [`docs/implementers-guide.md`](docs/implementers-guide.md) for the full algorithm and common pitfalls.


## CI: Cross-SDK Smoke Gate

Every protocol PR is validated against both consumer SDK CI gates that touch
the spec submodule. The `cross-sdk-smoke-python` and `cross-sdk-smoke-typescript`
jobs in `.github/workflows/ci.yml`:

1. Check out sanna-ai/sanna and sanna-ai/sanna-ts at their `main` branches.
2. Override each consumer's `spec/` submodule to point at the protocol PR's
   HEAD via `git fetch origin pull/<N>/head` (works for fork PRs because GitHub
   mirrors all PRs on the upstream).
3. Run each consumer's spec-touching CI gates using the same commands and
   environment that consumer's own CI uses:
   - **sanna-repo**: schema parity diff, `python -m pytest tests/ -v`, golden
     receipts verification (`sanna-verify`), example constitution verification
     (`sanna-sign-constitution`). All gated on `SANNA_ALLOW_TEMP_DB=1`.
   - **sanna-ts**: `npm run build`, then `npm test` with
     `SANNA_ALLOW_TEMP_DB=1`.
4. Fail the protocol PR if any gate fails.

The gate catches fixture-shape changes, schema breakage, signing or
canonicalization divergence, and operational schema-mirror drift at protocol
PR time -- before consumer SDKs bump the spec submodule.

### Why it exists

Prior to this gate, protocol changes that broke fixture consumers were only
detected when a consumer SDK's PR opened with the new submodule pin. The lag
window was hours to days. The smoke gate moves detection to protocol PR time.
Tradeoff: protocol PR CI duration increases from ~3 minutes to ~10-15 minutes.

### Failure interpretation

If the smoke gate fails, the failing job's logs identify which consumer broke
and which gate. The protocol PR's content is the suspected cause. If a
consumer's `main` is itself broken (independent of the protocol PR), the smoke
fails as a side effect; fix the consumer's `main` first, then rerun the gate.

### Local reproduction

To reproduce the smoke check locally before opening a PR:

```bash
# In a temp clone of sanna-ai/sanna or sanna-ai/sanna-ts:
cd spec
git fetch origin <your-protocol-pr-sha>
git checkout <your-protocol-pr-sha>
cd ..
# Then run the consumer's test commands (python -m pytest tests/ -v;
# or npm run build && npm test).
```

## Versioning

Protocol versions are independent of SDK versions. Patch versions (1.0.x) are clarifications and new test vectors. Minor versions (1.x.0) add backward-compatible fields. Major versions (x.0.0) are breaking changes to the receipt format, fingerprint algorithm, or signing protocol.

## License

[Apache 2.0](LICENSE)
