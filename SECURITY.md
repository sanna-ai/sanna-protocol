# Security Policy

## Supported Versions

Only the latest release on the default branch (`main`) is supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

**Email:** [security@sanna.dev](mailto:security@sanna.dev)

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

**Do not** open a public GitHub issue for security vulnerabilities.

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgement | Within 48 hours |
| Triage | Within 7 days |
| Fix timeline communicated | Within 14 days |

## Safe Harbor

Good-faith security researchers acting within this policy will not face legal action from Sanna AI. We consider security research conducted consistent with this policy to be authorized and will not pursue civil or criminal action.

## Scope

The following repositories are in scope:

- [sanna](https://github.com/sanna-ai/sanna)
- [sanna-ts](https://github.com/sanna-ai/sanna-ts)
- [sanna-openclaw](https://github.com/sanna-ai/sanna-openclaw)
- [sanna-protocol](https://github.com/sanna-ai/sanna-protocol)

The Sanna Cloud service ([api.sanna.cloud](https://api.sanna.cloud)) is also in scope.

## Out of Scope

- Social engineering (e.g., phishing)
- Denial of service (DoS/DDoS) attacks
- Third-party services and dependencies

## security.txt

Our `security.txt` file is available at:
[https://sanna.dev/.well-known/security.txt](https://sanna.dev/.well-known/security.txt)

## Credit

Researchers who report valid vulnerabilities will be credited (with their permission) in release notes.

## Bundle Verification Trust Anchor (SAN-403)

Sanna's evidence bundle (`*.bundle.zip`) is a self-contained ZIP archive
that carries a receipt, the governing constitution, and the public key(s)
needed to verify their Ed25519 signatures offline. Without an external
trust signal, a verifier cannot distinguish a legitimately signed bundle
from one that has been re-signed end-to-end by an attacker who packaged
their own public key inside the zip.

To establish a trustworthy verification verdict, supply a trust anchor:

```
sanna bundle-verify path/to/bundle.zip --trusted-key-ids ./trusted-keys.txt
```

Or via environment variable:

```
SANNA_TRUSTED_KEY_IDS=./trusted-keys.txt sanna bundle-verify path/to/bundle.zip
```

The trusted-keys file is a newline-separated list of 64-hex Ed25519 `key_id`s,
one per line, lowercase. `#` introduces a comment that terminates at end of
line. Empty lines are ignored. Malformed lines are rejected with file path
and line number. A file with zero non-empty lines is rejected. The same
surface is available on the TypeScript SDK as the third argument to
`verifyBundle(bundlePath, true, new Set([...]))`.

When no trust anchor is supplied, the verifier emits a warning banner to
stderr and the JSON result's `trust_anchored` field is `false`. Production
verification claims MUST be made with a curated trust anchor.

Empty Set (passed programmatically) is the explicit "trust nothing" signal
and fails closed. The `constitution.approval.*.signature` `key_id`s and
multi-signature constitution `key_id`s are NOT yet checked against the
trust anchor (known limitation; will be closed in a subsequent revision).

See spec Section 10.1 for the full normative semantics and the protocol
fixture `fixtures/bundle-trust-vectors.json` (Section 13.4) for the
cross-SDK conformance contract.

## Test Key Rotation (SAN-404)

A 2026-05-03 cloud beta security audit (AUDIT-006) flagged two committed
Ed25519 PEM PRIVATE KEYs in `fixtures/keypairs/`. Both have been rotated
and are now REVOKED:

| key_id (64-hex)                                                    | role          | status   |
|--------------------------------------------------------------------|---------------|----------|
| `6edb993769fb606cdd56c47335970a0b42d163bcb44b21db416e6ec43963af61` | test-author   | REVOKED  |
| `02dd2d06eb03568accb742fc2a7ce751f2716627dd8c50773a2fcf53c6412de6` | test-attacker | REVOKED  |

Receipts, bundles, or constitutions whose signature `key_id` matches
either of the values above MUST NOT be trusted, regardless of whether
the Ed25519 signature itself verifies. The corresponding private keys
were committed to a public repository and must be assumed compromised.

The current authoritative test_key_id values are pinned in
`fixtures/golden-hashes.json` (`test_key_id`, `test_attacker_key_id`)
and in `fixtures/bundle-trust-vectors.json` (`genuine_key_id`,
`attacker_key_id`). Cross-SDK tests should read those values
dynamically rather than hardcoding any specific 64-hex string.

Forward-only removal: the two old `.key` files have been deleted from
the working tree but remain reachable in git history at the commits
where they were originally introduced. Sanna does not rewrite git
history; the trust signal is the REVOKED note above plus the rotated
pinned key_ids in the golden artifacts. Any tooling that relied on the
old `.key` files being present at HEAD must update.

Going forward, a pre-commit hook (`.pre-commit-config.yaml`,
`detect-private-key`) blocks PEM private keys from entering the repo.
The same hook runs in CI on every pull request.
