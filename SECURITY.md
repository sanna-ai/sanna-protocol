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
