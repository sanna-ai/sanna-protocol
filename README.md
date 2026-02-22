# Sanna Protocol

Open specification for cryptographic governance receipts. When an AI agent acts, the Sanna Protocol evaluates the action against a constitution, enforces boundaries, and produces a signed receipt proving governance was applied. The receipt binds the policy document, the evaluation result, and the enforcement outcome into a single tamper-evident artifact using Ed25519 signatures and RFC 8785 JSON canonicalization.

## Repository Contents

| Path | Description |
|------|-------------|
| [`spec/`](spec/sanna-specification-v1.0.md) | Protocol specification v1.0 — receipt format, fingerprint construction, canonicalization, signing, verification |
| [`schemas/`](schemas/) | JSON Schema (2020-12) for [constitutions](schemas/constitution.schema.json) and [receipts](schemas/receipt.schema.json) |
| [`fixtures/`](fixtures/) | Golden test fixtures — test keypair, signed constitutions, 4 receipt variants, expected hashes |
| [`templates/`](templates/) | Starter constitutions: [privacy-focused](templates/privacy-focused.yaml), [developer](templates/developer.yaml), [locked-down](templates/locked-down.yaml) |
| [`http/`](http/header-conventions.md) | HTTP header conventions (`X-Sanna-Receipt`, `X-Sanna-Receipt-URL`, `X-Sanna-Verify`, `X-Sanna-Constitution`) |
| [`docs/`](docs/) | [Implementers guide](docs/implementers-guide.md), [protocol comparison](docs/protocol-comparison.md) (Sanna vs ORS v0.1) |

## Implementations

| Language | Package | Install |
|----------|---------|---------|
| Python | [`sanna`](https://pypi.org/project/sanna/) | `pip install sanna` |
| TypeScript | `@sanna/core` | Coming soon |

## Conformance Verification

A conformant implementation must produce identical hashes and fingerprints for identical inputs. The [`fixtures/`](fixtures/) directory contains everything needed to verify:

1. Load the test keypair from `fixtures/keypairs/`
2. For each receipt in `fixtures/receipts/`, recompute `context_hash`, `output_hash`, and the 12-field fingerprint
3. Compare all computed values against `fixtures/golden-hashes.json`
4. Verify Ed25519 signatures using the test public key

All hashes match → conformant. See [`docs/implementers-guide.md`](docs/implementers-guide.md) for the full algorithm and common pitfalls.

## Versioning

Protocol versions are independent of SDK versions. Patch versions (1.0.x) are clarifications and new test vectors. Minor versions (1.x.0) add backward-compatible fields. Major versions (x.0.0) are breaking changes to the receipt format, fingerprint algorithm, or signing protocol.

## License

[Apache 2.0](LICENSE)
