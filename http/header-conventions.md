# HTTP Header Conventions for Sanna Receipt Transport

**Status:** Draft
**Version:** 1.0
**Date:** 2026-02-22

---

## Overview

This document defines HTTP headers for transporting Sanna reasoning receipts
alongside REST API responses. These headers allow any HTTP-based API to
advertise governance enforcement without requiring clients to understand the
full receipt format.

The headers are designed for use by API gateways, middleware, and application
servers that integrate Sanna governance. They complement the MCP transport
path defined in the core specification.

---

## Headers

### `X-Sanna-Receipt`

Carries the full receipt inline as a Base64-encoded JSON string.

```
X-Sanna-Receipt: <base64-encoded receipt JSON>
```

- The value MUST be the RFC 4648 standard Base64 encoding (with padding) of
  the UTF-8 encoded receipt JSON.
- Implementations SHOULD use `X-Sanna-Receipt-URL` instead when the encoded
  receipt exceeds 8 KB, to avoid exceeding common header size limits.
- When both `X-Sanna-Receipt` and `X-Sanna-Receipt-URL` are present, the
  inline header takes precedence.

**Example:**

```
X-Sanna-Receipt: eyJzcGVjX3ZlcnNpb24iOiIxLjAiLC...
```

### `X-Sanna-Receipt-URL`

Points to a URL where the full receipt can be fetched.

```
X-Sanna-Receipt-URL: <URL where full receipt can be fetched>
```

- The URL MUST return `application/json` with the receipt as the response body.
- The URL SHOULD be stable for the lifetime of the receipt (i.e., receipts
  are immutable once generated).
- Clients MUST validate the fetched receipt independently (schema validation,
  fingerprint verification, and optionally signature verification).

**Example:**

```
X-Sanna-Receipt-URL: https://api.example.com/sanna/receipts/a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
```

### `X-Sanna-Verify`

Identifies the public key needed to verify the receipt signature.

```
X-Sanna-Verify: <public-key-id>
```

- The value is the 64-character lowercase hex SHA-256 fingerprint of the
  Ed25519 public key (computed from the raw 32-byte public key, as specified
  in Section 5.5 of the Sanna Protocol specification).
- Clients can use this key ID to look up the corresponding public key from a
  trusted key directory or from a previously exchanged key bundle.

**Example:**

```
X-Sanna-Verify: 3a7f2b1c9e8d4f6a5b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a
```

### `X-Sanna-Constitution`

Identifies the constitution document that governed the request.

```
X-Sanna-Constitution: <document_id>/<version>
```

- The value follows the `document_id` format from `constitution_ref` in the
  receipt schema: `{agent_name}/{version}`.
- This header allows clients to verify they are interacting with an agent
  operating under a known governance policy without parsing the full receipt.

**Example:**

```
X-Sanna-Constitution: finance-agent/1.2.0
```

---

## Usage Patterns

### Minimal (receipt URL only)

For APIs where header size is constrained:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Sanna-Receipt-URL: https://api.example.com/sanna/receipts/abc123
X-Sanna-Verify: 3a7f2b...
X-Sanna-Constitution: finance-agent/1.2.0
```

### Full inline receipt

For APIs where clients need immediate verification without a second fetch:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Sanna-Receipt: eyJzcGVjX3ZlcnNpb24iOiIxLjAiLC...
X-Sanna-Verify: 3a7f2b...
X-Sanna-Constitution: finance-agent/1.2.0
```

### Blocked request

When enforcement halts a request, the receipt documents the governance decision:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-Sanna-Receipt: eyJzdGF0dXMiOiJGQUlMIiwi...
X-Sanna-Verify: 3a7f2b...
X-Sanna-Constitution: finance-agent/1.2.0

{"error": "Request blocked by governance policy", "receipt_fingerprint": "a1b2c3d4e5f6a7b8"}
```

---

## Security Considerations

- Receipt URLs MUST use HTTPS in production. HTTP URLs SHOULD be rejected
  by clients unless explicitly configured for development use.
- The `X-Sanna-Verify` header is informational. Clients MUST NOT trust the
  key ID blindly — they must verify the public key is in their trust store.
- Inline receipts in `X-Sanna-Receipt` are subject to the same verification
  requirements as receipts fetched from any other source.
- Proxies and CDNs MUST NOT cache or strip `X-Sanna-*` headers, as they are
  integrity-critical metadata.
