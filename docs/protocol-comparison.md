# Protocol Comparison: Sanna Protocol vs Open Receipt Specification (ORS)

Both protocols use Ed25519 signatures with RFC 8785 JSON canonicalization
for AI agent governance receipts. They address different aspects of the
agent trust problem.

## Scope

| Dimension | Sanna Protocol v1.0 | ORS v0.1 |
|-----------|---------------------|----------|
| Governance model | Constitution-as-code (YAML) with invariants, boundaries, and halt conditions | 7 rule types (flat list) |
| Relationship axis | Organization to Agent | Agent to API Provider |
| Constraint types | Deterministic + semantic (LLM-evaluated checks) | Deterministic only |
| Enforcement levels | `can_execute` / `must_escalate` / `cannot_execute` | allow / deny / escalate |
| Receipt binding | Constitution content hash (SHA-256) | Terms reference |
| Verification | Offline — no central endpoint required | Centralized (openterms.com) |
| Deployment modes | Library / Gateway / Platform | SaaS API |
| Domain scope | General-purpose (any agent, any domain) | Financial transactions |
| Fingerprint construction | 12-field pipe-delimited SHA-256 | Receipt hash |
| Canonicalization | Sanna Canonical JSON (RFC 8785 derived, NFC normalized) | RFC 8785 JSON Canonicalization Scheme |
| Key identification | SHA-256 of raw 32-byte Ed25519 public key | Key reference |
| Approval chain | Cryptographic approval binding with HMAC-SHA256 escalation tokens | Not specified |
| PII handling | Deterministic redaction markers with original_hash | Not specified |
| Receipt Triad | input_hash / reasoning_hash / action_hash binding | Not specified |
| Evidence bundles | ZIP archive with receipt, constitution, public keys | Not specified |

## Shared Primitives

- Ed25519 signatures (RFC 8032, Pure Ed25519)
- RFC 8785 JSON Canonicalization Scheme (as basis)
- SHA-256 content hashing
- Domain-separated signature prefixes
- Pre-execution policy enforcement
- Open specification separated from implementation

## Design Philosophy

The Sanna Protocol treats the constitution as the primary governance artifact.
A constitution defines what an agent can do, what it must escalate, and what
it cannot do — with cryptographic binding between the policy document and every
receipt the agent generates. This makes governance auditable end-to-end: from
the policy definition, through enforcement, to the signed receipt.

ORS focuses on the transaction boundary between an agent and an API provider,
providing a receipt that the API call complied with the provider's terms of
service.

The two protocols are complementary. An agent could operate under a Sanna
constitution (defining its internal governance) while also generating ORS
receipts (proving compliance with external API terms) for outbound calls.
