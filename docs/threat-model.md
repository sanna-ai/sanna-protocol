# Sanna Protocol Threat Model

**Status:** Draft
**Document version:** 1.0
**Spec version:** 1.5
**Date:** 2026-05-12
**Approach:** STRIDE-style per-component analysis with explicit assets, attacker
capabilities, mitigations, and out-of-scope assumptions.

This document is a complement to the spec's informal Security Considerations
section (Sanna Specification v1.5 Section 12). The spec provides the normative
summary; this document provides the analytical depth: trust boundaries, asset
enumeration, STRIDE category per component, mitigation references, and open
questions.

---

## Provenance

This document is a self-assessment authored by the protocol designer. It has not
been reviewed by an independent third party as of the date above. External review
is tracked separately; the status section above will be updated in this document
when external review occurs. Readers SHOULD NOT interpret the absence of
identified threats as evidence that none exist -- only as evidence that the author
did not identify them.

The historical security audit referenced throughout this document
(`security-audit-sanna-protocol-2026-03-26.md`) is itself an automated audit
(performed by Anthropic Claude), not a third-party human assessment. References
to specific finding IDs (e.g., `C-SPEC-1`, `H-SPEC-2`) describe attack surfaces
identified by that automated audit and cross-referenced against the current v1.5
spec. Every such citation in this document is annotated as **ADDRESSED**,
**PARTIAL**, or **OPEN** against current v1.5 spec text after direct
verification.

---

## 1. System Overview

### 1.1 Trust Boundaries

The Sanna receipt protocol operates across four distinct trust boundaries:

**Boundary 1: Agent/LLM boundary.**
The AI agent (the governed system) is untrusted. It may produce arbitrary text,
arbitrary tool call arguments, and may attempt prompt injection. The Sanna
middleware and gateway enforce policy against agent outputs but cannot verify the
agent's internal state or reasoning integrity -- only what it outputs.

**Boundary 2: Governance runtime boundary.**
The Sanna runtime (Python `sanna` or TypeScript `@sanna/core`) executes on the
same host as the agent and signs receipts. This boundary is trusted: if the
Sanna library is modified or the process memory is compromised, receipts can be
forged at the source. Sanna does not defend against compromised runtime
environments (see Section 4.3).

**Boundary 3: Receipt persistence and transit boundary.**
Receipts are written to disk or transmitted to storage (e.g., Sanna Cloud
ingestion). At this boundary, receipts may be read by unauthorized parties,
modified in transit, or selectively deleted. Ed25519 signatures and deterministic
fingerprints detect modification of signed receipts; unsigned receipts have no
cryptographic integrity at this boundary.

**Boundary 4: Verifier boundary.**
A verifier (human or automated) consumes receipts and produces a verdict. The
verifier must supply an out-of-band trust anchor (`SANNA_TRUSTED_KEY_IDS`) to
distinguish a legitimately signed bundle from one re-signed by an attacker with
their own keypair packaged inside. Without a trust anchor, the verifier's
`trust_anchored` field is `false` and no production verification claim should be
made (spec Section 10.1).

### 1.2 Actors

| Actor | Role | Trust Level |
|-------|------|-------------|
| AI Agent (LLM) | Generates outputs subject to governance | **Untrusted** |
| Sanna Middleware | Intercepts agent outputs; evaluates checks; signs receipts | Trusted runtime |
| Sanna Gateway | Proxy that evaluates tool calls against authority boundaries; enforces halt/escalate | Trusted runtime |
| Constitution Author | Creates and signs constitutions | Trusted, out-of-band |
| Constitution Approver | Signs approval records binding constitutions to deployments | Trusted, out-of-band |
| Escalation Approver (human) | Responds to must_escalate prompts | Trusted, interactive |
| Receipt Verifier (downstream) | Reads receipts, verifies fingerprint/signature, makes trust decisions | Semi-trusted consumer |
| Receipt Storage (Sanna Cloud) | Ingests and stores receipts; enforces content_mode contract | Trusted service |
| Attacker | Controls agent outputs; can read persisted artifacts; may attempt MITM, replay, or injection | **Hostile** |

### 1.3 Data Flows

The following data flows describe how governed artifacts move through the system:

**Flow A: Receipt generation (middleware path).**
Agent input and output -> `@sanna_observe` decorator or MCP server tool -> C1-C5
reasoning checks -> enforcement action -> receipt construction -> fingerprint
computation (Section 4) -> optional Ed25519 signing (Section 5) -> persisted to
disk or sent to Sanna Cloud.

**Flow B: Receipt generation (gateway path).**
MCP tool call from agent -> gateway enforcement proxy -> authority boundary
evaluation (can_execute / cannot_execute / must_escalate) -> halt, allow, or
escalation receipt -> HMAC token issuance (Section 8.2) -> human approval channel
(stderr or webhook) -> resolution receipt -> persisted to disk.

**Flow C: Constitution loading.**
YAML constitution file -> signature verification (Ed25519, using author public
key) -> policy_hash recomputation -> constitution loaded into enforcement context.

**Flow D: Evidence bundle verification.**
Bundle ZIP (receipt + constitution + public keys) -> 8-step verification
(Section 10) -> verifier result including trust_anchored field.

**Flow E: Escalation approval.**
Pending escalation stored with HMAC token -> human sees tool name + args via
stderr or webhook delivery -> human provides token -> token verified via
HMAC-SHA256 recomputation -> escalation resolved -> resolution receipt generated.

---

## 2. Assets

This section enumerates assets that an attacker would target, their lifecycle,
and their integrity/confidentiality/availability requirements.

### 2.1 Receipt Integrity (Signed)

**What it is:** The receipt JSON object, including the fingerprint and
`receipt_signature` block. A signed receipt provides cryptographic proof that
governance checks ran and that the receipt has not been tampered with.

**Lifecycle:** Created by Sanna middleware/gateway at enforcement time. Written
to disk or sent to Sanna Cloud. Read by downstream verifiers.

**Why an attacker targets it:** A forged or modified receipt that reads
`status: "PASS"` can be presented as proof of governance enforcement that never
occurred, or as proof that a halted action was allowed.

**Requirements:** Integrity MUST be preserved across transit and at rest.
Confidentiality depends on whether the receipt contains PII (see Section 2.6).
Availability: a destroyed receipt erases the audit trail.

### 2.2 Signing Keypairs (Ed25519)

**What it is:** The Ed25519 private key used to sign receipts (gateway keypair)
and constitutions (author keypair). The corresponding public key is the
verification anchor.

**Lifecycle:** Generated once per role. Private key stored at rest (filesystem,
0o600 recommended). Public key distributed out-of-band to verifiers.

**Why an attacker targets it:** Possession of a private key enables forging
arbitrarily many valid signed receipts or constitutions.

**Requirements:** Integrity and confidentiality of private keys are paramount.
Key management is operational, not protocol-enforced (see Section 4.3).

### 2.3 Fingerprint Determinism (Canonical JSON Byte Parity)

**What it is:** The guarantee that two conformant implementations produce
byte-identical fingerprints for identical inputs. The fingerprint is a
pipe-delimited SHA-256 of selected receipt fields (spec Section 4).

**Lifecycle:** Computed by the Sanna runtime at receipt creation. Recomputed by
the verifier at verification time.

**Why an attacker targets it:** If two implementations diverge in fingerprint
computation, a legitimate receipt from Implementation A will appear tampered when
verified by Implementation B, undermining the cross-SDK trust claim.

**Requirements:** Determinism across Python and TypeScript implementations. The
canonicalization test vectors (`fixtures/canonicalization-vectors.json`) are the
normative cross-SDK contract.

### 2.4 Constitution Provenance (Signed YAML)

**What it is:** The constitution YAML file and its Ed25519 signature. The
signature covers the canonical signable form (Section 5.3), which includes
governance boundaries, invariants, and (in v2) cli/api permissions.

**Lifecycle:** Authored and signed offline by the constitution author. Loaded by
the Sanna runtime at startup. Referenced in receipts via `constitution_ref`.

**Why an attacker targets it:** A modified constitution can expand what the agent
is allowed to do (adding can_execute entries, removing cannot_execute entries) or
weaken invariants. If the signature does not cover the modification, it passes
signature verification while being materially different from the approved policy.

**Requirements:** Integrity of the constitution at load time. The approval chain
(Section 2.5) provides a second layer of provenance.

### 2.5 Constitution Approval Chain

**What it is:** The `constitution_approval` block in a receipt and the
`ApprovalRecord` objects in the constitution, each signed by the approver keypair.
HMAC tokens bind escalation approvals to specific tool calls (Section 8.2).

**Lifecycle:** Approval records are created by the constitution approver and
embedded in the constitution. HMAC tokens are created at escalation time by the
gateway and consumed on approval or denial.

**Why an attacker targets it:** Forging an approval record allows bypassing the
must_escalate enforcement path. Replaying a consumed HMAC token allows reusing a
past approval for a different tool call.

**Requirements:** Integrity of approval records and HMAC tokens. Token one-time
use enforced by removal from escalation store after consumption (Section 8.3).

### 2.6 Audit Trail (Receipt Chaining)

**What it is:** The chain of receipts linked via `parent_receipts` (Section 2.12)
and the escalation pair (escalation receipt + resolution receipt, Section 8.1).
The audit trail proves the sequence of governed actions.

**Lifecycle:** Built incrementally as governed actions occur. Each receipt's
`parent_receipts` field hashes the parent receipts into the fingerprint (field 13
at cv >= 6).

**Why an attacker targets it:** Deleting or reordering receipts can hide
governance failures. Inserting fabricated receipts can create a false audit
history.

**Requirements:** Append-only at the storage layer (cloud implementation
responsibility; not enforced by the protocol itself). Integrity of the chaining
hash provides detection of tampering on signed receipts.

### 2.7 Redaction Markers (Pre-image Security)

**What it is:** Redaction markers replace PII in receipt content fields with a
`{"__redacted__": true, "original_hash": "<sha256>"}` object (spec Section 2.11).
The `original_hash` is the SHA-256 of the NFC-normalized original value.

**Lifecycle:** Applied by the gateway before signing. The signed receipt contains
the marker; the original value is never persisted to disk.

**Why an attacker targets it:** If the SHA-256 hash of a low-entropy value (a
phone number, a short identifier) can be brute-forced, the attacker can recover
the original content from the redacted receipt. This is a rainbow-table attack on
the hash.

**Requirements:** Pre-image resistance of SHA-256 (algorithmic) and high entropy
of original values (operational). Low-entropy inputs are a known residual risk
(see Section 3.4 and Section 5).

---

## 3. STRIDE Analysis

The automated audit (Anthropic Claude) dated 2026-03-26
(`security-audit-sanna-protocol-2026-03-26.md`) covered the v1.2 spec. Where
findings from that audit are cited, each is verified against the current v1.5
spec and labeled **ADDRESSED**, **PARTIAL**, or **OPEN**. The labels apply to the
protocol specification's treatment of the threat; they do not necessarily mean
the threat is eliminated -- implementation and operational gaps remain for some
ADDRESSED findings (see Section 4).

### 3.1 Spoofing

Spoofing attacks impersonate a trusted actor or artifact. In the receipt
protocol, the primary spoofing surfaces are: the receipt issuer (who signed the
receipt?), the constitution issuer (who signed the policy?), and the approval
channel (who approved the escalation?). The protocol defends against spoofing
primarily through Ed25519 signatures and HMAC token binding, but these defenses
depend on the integrity of the key material and the trust anchor.

**Scenario S-1: Forged Ed25519 signatures (stolen gateway key)**

*Description.* An attacker who has obtained the Ed25519 private key used to sign
receipts can produce arbitrary valid-signature receipts. The attacker can claim
any governance outcome, including `status: "PASS"` with `enforcement.action:
"allowed"` for actions that were never evaluated. The receipt will pass all
signature verification steps.

*Affected assets.* Receipt integrity (Section 2.1), Ed25519 keypairs (Section
2.2).

*Mitigation.* Key management (spec Section 12.4): private keys MUST be stored
with restricted permissions (0o600 or equivalent). Per-role keypair separation
(RECOMMENDED) limits blast radius -- a stolen gateway key does not compromise
constitution signing or approval signing. Key rotation is the recovery path
(Section 12.4). **Protocol-mandated:** key separation and file permission
requirement. **Implementation-mandated:** actual enforcement of file permissions,
key storage at rest security.

*Residual risk.* Protocol cannot defend against theft of a properly managed key.
Key compromise is an operational incident; the protocol has no revocation
mechanism. Mitigation relies entirely on operational key management practices.

---

**Scenario S-2: Public key substitution (bundle re-sign attack)**

*Description.* An attacker who intercepts an evidence bundle can replace the
receipt and constitution with forged versions signed by the attacker's own
keypair, then package the attacker's public key inside the bundle. Without an
out-of-band trust anchor, the verifier cannot distinguish this from a legitimate
bundle.

*Affected assets.* Receipt integrity (Section 2.1), audit trail (Section 2.6).

*Mitigation.* Trust anchor requirement (spec Section 10.1): operators MUST supply
`--trusted-key-ids` (or `SANNA_TRUSTED_KEY_IDS`) for any production verification
claim. Without it, the verifier emits a warning banner and the result's
`trust_anchored` field is `false`. **Protocol-mandated:** the trust_anchored field
and warning banner. **Implementation-mandated:** operators supplying and
maintaining the trusted key ID list out-of-band.

*Residual risk.* The warning banner is advisory. An automated pipeline that
consumes verifier output without checking `trust_anchored` will be fooled. The
spec MUST requirement applies to operators; the protocol cannot enforce it.

---

**Scenario S-3: Constitution issuer impersonation**

*Description.* An attacker substitutes a malicious constitution (with weakened
boundaries or broader can_execute scope) for the legitimate one. The attacker
signs it with their own keypair, which the gateway loads without verifying the
author key against a trusted allowlist.

*Affected assets.* Constitution provenance (Section 2.4), receipt integrity
(Section 2.1).

*Mitigation.* Constitution Ed25519 signing (spec Section 5.3). The signed
canonical form (v2) now covers all governance-critical fields including
`cli_permissions` and `api_permissions` (Section 5.3, ADDRESSED from H-SPEC-7
of the automated audit against v1.2 spec -- v1.2 did not include these fields in
the signature). Verifiers MUST check the constitution signature against a known
author public key. **Protocol-mandated:** constitution signing requirement.
**Implementation-mandated:** operators maintaining a trusted author key list; the
protocol does not specify how authors publish their keys.

*Residual risk.* If the author public key is itself substituted (see S-2 pattern
applied to constitution), the same re-sign attack applies. Constitution trust
ultimately reduces to key management.

---

**Scenario S-4: Approval channel impersonation (webhook DNS poisoning)**

*Description.* An attacker who controls DNS or network routing redirects a
webhook escalation notification to an attacker-controlled server. The attacker
approves the escalation directly, bypassing the intended human approver.

*Affected assets.* Constitution approval chain (Section 2.5).

*Mitigation.* HMAC token binding (spec Section 8.2): the approval token is bound
to a specific tool name, escalation ID, arguments digest, and issued_at timestamp.
A token captured by a DNS-spoofing attacker can only approve the specific tool
call it was issued for. Spec Section 12.5 requires implementations to validate
webhook URLs (MUST reject private IP ranges and non-HTTPS URLs, SHOULD use TLS).
**Protocol-mandated:** HMAC binding and webhook SSRF validation requirement (spec
Section 12.5). **Implementation-mandated:** TLS certificate validation, IP range
filtering.

*Residual risk.* HMAC token binding does not prevent an attacker from approving
the specific captured escalation. The attacker still gets to approve the one tool
call they intercepted. Defense requires network-layer controls (TLS, IP allow
lists) beyond the protocol.

---

**Scenario S-5: Receipt issuer impersonation via tool_name enum gaming**

*Description.* The `tool_name` field identifies which enforcement surface issued
the receipt (via the `sanna-`, `mcp-`, `gw-` prefix convention). An attacker who
controls receipt construction (on an unsigned receipt) can set `tool_name` to a
value that implies a different surface (e.g., claim a middleware receipt is a
gateway receipt, where authority boundary checking occurs).

*Affected assets.* Receipt integrity (Section 2.1), audit trail (Section 2.6).

*Mitigation.* `tool_name` participates in the fingerprint (field 17 at cv >= 9,
spec Section 4.1) and is covered by the receipt signature when signing is used.
On signed receipts, modification of `tool_name` invalidates the fingerprint and
signature. **Protocol-mandated:** tool_name in fingerprint (cv >= 9) and signature
coverage. **Open gap:** on unsigned receipts, tool_name can be changed and the
fingerprint recomputed by the attacker (see H-SPEC-2 pattern in Section 3.2
below).

*Residual risk.* Unsigned receipts cannot defend against this. The `enforcement_surface`
field (spec Section 2.16) provides a more explicit provenance signal and also
participates in the fingerprint (field 15 at cv >= 8).

---

### 3.2 Tampering

Tampering attacks modify an artifact after creation. In the receipt protocol,
the primary tampering surfaces are: receipt mutation (status, enforcement,
checks), fingerprint recomputation (on unsigned receipts), and constitution policy
mutation (after signing but before loading). The Ed25519 signature and
deterministic fingerprint are the primary anti-tampering mechanisms -- but both
rely on receipts being signed, which is optional.

**Scenario T-1: Receipt mutation on signed receipts**

*Description.* An attacker modifies a field of a signed receipt (e.g., changing
`status` from `"FAIL"` to `"PASS"`). The Ed25519 signature covers the entire
receipt via `canonical_json_bytes()` of the signed form (spec Section 5.2). The
modification invalidates the signature, which the verifier detects.

*Affected assets.* Receipt integrity (Section 2.1).

*Mitigation.* Ed25519 signature (spec Section 5.2): any modification to a signed
receipt invalidates the signature, producing a verification error at step 7 of the
verification protocol (spec Section 9.1). **Protocol-mandated:** signing and
verification procedures.

*Residual risk.* Mitigation is contingent on the receipt being signed
(`receipt_signature` is optional -- see S-1 and T-2).

---

**Scenario T-2: Status field manipulation on unsigned receipts (C-SPEC-1)**

*Description.* On an unsigned receipt, an attacker changes `status` from
`"FAIL"` to `"PASS"`, zeroes `checks_failed`, and sets `checks_passed` to match.
The fields `status`, `checks_passed`, and `checks_failed` are NOT in the
fingerprint formula (spec Section 4.5). The attacker recomputes the fingerprint
with no other changes, and the fingerprint validates.

This is finding C-SPEC-1 from the automated audit (Anthropic Claude) against
v1.2. Status: **PARTIAL** against v1.5.

*Partial mitigation in v1.5.* Section 4.6 (added in v1.3) requires verifiers to
MUST-level assert that `status` is consistent with `enforcement.action` when the
`enforcement` field is present -- a mismatch produces a verification error (exit
code 4). Additionally, verification step 4 (spec Section 9.1) requires status
consistency checking against the checks array. If the attacker modifies `status`
but not `enforcement.action`, the cross-field check catches the inconsistency.

*Remaining gap.* If the attacker also strips or modifies `enforcement` (see T-3),
the Section 4.6 check does not apply (per spec line: "When enforcement is absent
or null, this check does not apply"). An attacker who sets `enforcement: null`
and `status: "PASS"` on an unsigned receipt can pass verification step 4 (no
enforcement to check against) while misrepresenting the governance outcome.
Status is still not in the fingerprint formula in v1.5.

*Affected assets.* Receipt integrity (Section 2.1), audit trail (Section 2.6).

*Mitigation.* Signing is the authoritative defense (T-1). Cross-field consistency
check (Section 4.6) partially mitigates for receipts where enforcement is present.
**Protocol-mandated:** Section 4.6 consistency check. **Implementation-mandated:**
verifier correctly implements step 4 and step 6.

*Residual risk.* Unsigned receipts remain vulnerable to status manipulation when
enforcement is also stripped or absent.

---

**Scenario T-3: Enforcement erasure on unsigned receipts (H-SPEC-2)**

*Description.* The `enforcement` field is present in a receipt recording a halted
action (`enforcement.action: "halted"`, `status: "FAIL"`). An attacker strips the
`enforcement` field from an unsigned receipt. The `enforcement_hash` field in the
fingerprint becomes `EMPTY_HASH` (the SHA-256 of the empty string, per spec
Section 4.1). The attacker also sets `status: "PASS"` and recomputes the
fingerprint, which now matches a receipt that never had enforcement.

This is finding H-SPEC-2 from the automated audit (Anthropic Claude) against
v1.2. Status: **OPEN** against v1.5 for unsigned receipts.

*Affected assets.* Receipt integrity (Section 2.1), audit trail (Section 2.6).

*Mitigation.* On signed receipts, stripping enforcement invalidates the signature.
`enforcement_surface` (spec Section 2.16) participates in the fingerprint (field
15 at cv >= 8) and provides provenance -- but does not restore integrity of the
enforcement object itself on unsigned receipts.

*Residual risk.* Unsigned receipts remain fully vulnerable. The distinction between
"never had enforcement" and "enforcement stripped" is cryptographically invisible
on unsigned receipts.

---

**Scenario T-4: Fingerprint pre-image attack (deliberate collision)**

*Description.* An attacker constructs two different receipts with the same
pipe-delimited fingerprint input string. SHA-256 pre-image resistance makes this
computationally infeasible with current hardware. The scenario is theoretical for
SHA-256 but relevant as a protocol design consideration.

*Affected assets.* Fingerprint determinism (Section 2.3), receipt integrity
(Section 2.1).

*Mitigation.* SHA-256 is the hash function used (spec Section 3.3). No known
practical pre-image attack exists against SHA-256. **Protocol-mandated:** SHA-256
selection.

*Residual risk.* Post-quantum SHA-256 preimage resistance is an open question at
longer time horizons, though SHA-256 is not known to be vulnerable to quantum
speedup for preimage attacks. See Section 5.

---

**Scenario T-5: Version rollback via spec_version field manipulation (H-SPEC-4)**

*Description.* `spec_version` and `tool_version` are NOT in the fingerprint
formula (spec Section 4.5, explicitly listed). An attacker changes `spec_version`
from `"1.5"` to `"1.0"` on an unsigned receipt. A verifier that selects
verification logic based on `spec_version` might apply weaker (older) rules.

This is finding H-SPEC-4 from the automated audit (Anthropic Claude) against
v1.2. Status: **OPEN** against v1.5 -- `spec_version` is still explicitly
excluded from the fingerprint (spec Section 4.5).

*Affected assets.* Receipt integrity (Section 2.1).

*Mitigation.* On signed receipts, modifying `spec_version` invalidates the
signature (the signature covers the full receipt). The risk applies only to
unsigned receipts. The verifier does dispatch on `checks_version` (as integer,
spec Section 4.4), which IS in the fingerprint (field 4). An attacker cannot
change `checks_version` on an unsigned receipt without breaking the fingerprint.
The attack surface is `spec_version` specifically, where a verifier uses it to
select logic separately from `checks_version`.

*Residual risk.* Unsigned receipts allow `spec_version` manipulation. Verifiers
should not use `spec_version` as the primary dispatch signal; `checks_version`
(which is in the fingerprint) is the load-bearing version field.

---

**Scenario T-6: Constitution policy mutation post-signature**

*Description.* An attacker modifies the constitution YAML after it has been
signed, widening the can_execute list or removing cannot_execute entries. The
constitution Ed25519 signature no longer matches the modified content.

*Affected assets.* Constitution provenance (Section 2.4).

*Mitigation.* Ed25519 constitution signature (spec Section 5.3, v2 canonical
form). The v2 canonical form covers `cli_permissions` and `api_permissions` in
addition to the core policy fields. **ADDRESSED** from H-SPEC-7 of the automated
audit (Anthropic Claude) against v1.2 -- v1.2 did not cover these fields in the
constitution signature. The verifier MUST verify the constitution signature at
bundle verification step 4 (spec Section 10). **Protocol-mandated.**

*Residual risk.* Constitution signature verification requires the author public
key. The policy_hash (in receipt `constitution_ref`) covers a subset of fields
(spec Section 5.3 note on `policy_hash scope`) and does NOT cover cli_permissions
or api_permissions. A receipt's `policy_hash` therefore does not detect changes to
cli/api permission blocks; only the full constitution signature does.

---

### 3.3 Repudiation

Repudiation attacks allow an actor to deny that an action occurred or that
governance was enforced. In the receipt protocol, repudiation surfaces include:
incomplete audit trails (no receipt for a governed action), deniable enforcement
(a FAIL receipt with no enforcement record), and receipt backdating (presenting
past events with manipulated timestamps). The append-only audit trail and HMAC
token binding are the primary anti-repudiation mechanisms.

**Scenario R-1: Lost audit trail (no receipts emitted)**

*Description.* An actor claims that a governed action was not taken, or that
governance was enforced, when in fact the Sanna runtime was not in the agent's
execution path and no receipt was ever generated. The agent executed tool calls
directly without going through the gateway or middleware.

*Affected assets.* Audit trail (Section 2.6).

*Mitigation.* Sanna is an observational system. The spec explicitly acknowledges
this limitation (spec Section 12.3: "Bypassing Sanna entirely: If the agent can
execute tool calls without going through the gateway or middleware, no receipt is
generated."). This is out-of-scope for the protocol. **Architectural.** Defense
requires process isolation controls at the deployment layer, not the protocol
layer (see Section 4.3).

*Residual risk.* Protocol cannot prevent receipt omission. This is a fundamental
architectural limitation acknowledged in the spec.

---

**Scenario R-2: Deniable enforcement (FAIL receipt without enforcement action)**

*Description.* A buggy or malicious implementation detects critical governance
failures (C1-C5 checks fail), records them in the receipt (`status: "FAIL"`,
checks_failed > 0), but omits the enforcement field (`enforcement: null`). The
governed action proceeds without being halted. The receipt appears to document
governance but provides no evidence that enforcement actually occurred.

This is finding C-SPEC-2 from the automated audit (Anthropic Claude) against
v1.2. Status: **PARTIAL** against v1.5.

*Partial mitigation in v1.5.* Verification step 6 (spec Section 9.1) issues a
warning for "FAIL + no enforcement." Section 4.6 cross-field consistency check
requires that when `enforcement` IS present, `status` MUST match
`enforcement.action`. A verifier that promotes step 6 from "warning only" to
"error" at the application layer provides stronger enforcement. **Protocol-
mandated:** step 6 warning. **Not yet protocol-mandated:** step 6 as an error.

*Remaining gap.* Step 6 is explicitly "warning only" in the current spec (Section
9.1). An auditor who accepts receipts without checking for this warning will not
detect the gap. The protocol does not mandate that enforcement is present when
status is FAIL.

*Affected assets.* Audit trail (Section 2.6), receipt integrity (Section 2.1).

*Residual risk.* A FAIL receipt with null enforcement is a valid receipt under the
current spec. Applications that rely on receipts as enforcement evidence MUST
check for this condition. The warning-only treatment is a known open gap in the
protocol (not yet filed as a separate improvement ticket as of this document's
date).

---

**Scenario R-3: Receipt backdating (timestamp not in fingerprint)**

*Description.* An attacker modifies the `timestamp` field of an unsigned receipt
to claim the governance evaluation occurred at a different time. The `timestamp`
field is NOT in the fingerprint formula (spec Section 4.5, explicitly listed). On
an unsigned receipt, the attacker can set any timestamp and recompute the
fingerprint.

This is finding M-SPEC-2 from the automated audit (Anthropic Claude) against
v1.2. Status: **OPEN** against v1.5 -- `timestamp` is still explicitly excluded
from the fingerprint (spec Section 4.5).

*Affected assets.* Audit trail (Section 2.6), receipt integrity (Section 2.1).

*Mitigation.* On signed receipts, timestamp modification invalidates the signature.
The receipt chaining mechanism (`parent_receipts` in field 13 of the fingerprint)
creates a partial temporal ordering -- a receipt cannot claim to precede its
parent. **Protocol-mandated for signed receipts:** signature coverage. **Open:**
timestamp attestation for unsigned receipts.

*Residual risk.* Unsigned receipts allow arbitrary timestamp manipulation. The
protocol cannot provide temporal ordering guarantees for unsigned receipts.

---

**Scenario R-4: Bypassing Sanna entirely**

*Description.* An agent operating outside the Sanna gateway or middleware
executes tool calls without any receipt being generated. From the audit trail
perspective, the action simply did not happen. There is nothing to repudiate
because there is no receipt.

*Affected assets.* Audit trail (Section 2.6).

*Mitigation.* None within the protocol. This is an acknowledged limitation (spec
Section 12.3). **Out of scope** (see Section 4.3).

*Residual risk.* Fundamental limitation. Deployment must ensure the Sanna runtime
is in the critical path for all governed actions.

---

### 3.4 Information Disclosure

Information disclosure attacks expose sensitive data to unauthorized parties. In
the receipt protocol, the primary disclosure surfaces are: PII in receipt content
fields, approval tokens in logs, redaction marker pre-image attacks, and key
material correlation.

**Scenario I-1: PII leakage in receipt content fields**

*Description.* The `inputs` and `outputs` objects in a receipt contain the
agent's context and output. In many deployments this includes PII (personal
information, medical data, financial records). These fields are included in the
fingerprint (as `context_hash` and `output_hash`) and in the receipt signature,
but the raw values are stored in the receipt JSON and may be written to disk or
sent to Sanna Cloud.

*Affected assets.* Receipt content fields.

*Mitigation.* Redaction markers (spec Section 2.11): when PII redaction is
enabled, original values are replaced with marker objects before signing. The
receipt persisted to disk contains only the hash of the original value, not the
value itself (Section 2.11.5). `content_mode` (spec Section 2.14) controls
whether raw content or metadata-only receipts are sent to Sanna Cloud.
**Protocol-mandated:** redaction marker format and pre-existing marker injection
guard (Section 2.11.4). **Implementation-mandated:** enabling redaction is an
operator choice; it is not required by the protocol.

*Residual risk.* Redaction is opt-in. Operators who do not enable redaction
persist raw PII in receipts. The protocol documents the capability but cannot
mandate its use.

---

**Scenario I-2: Receipt content exfiltration via persistent storage**

*Description.* Receipts are written to disk with content intact. An attacker with
read access to the receipt storage directory (local filesystem, cloud storage) can
read all receipt content without any cryptographic barrier. Receipts are not
encrypted at rest by the protocol.

*Affected assets.* Receipt content fields.

*Mitigation.* The protocol does not specify encryption at rest. This is out of
scope (see Section 4.3). Filesystem permissions and cloud storage access controls
are the appropriate mitigations. **Operational.**

*Residual risk.* Protocol cannot address this. Deployment must apply access
controls at the storage layer.

---

**Scenario I-3: Redaction marker pre-image attack (low-entropy values)**

*Description.* Redaction markers store `original_hash`: the SHA-256 of the
NFC-normalized original value. For low-entropy values (e.g., a 10-digit phone
number has ~33 bits of entropy, a 9-digit SSN has ~30 bits), a pre-image attack
is computationally feasible. An attacker with the redacted receipt can generate a
rainbow table of candidate values and their SHA-256 hashes, then match against
`original_hash` to recover the original content.

*Affected assets.* Redaction markers (Section 2.7).

*Mitigation.* SHA-256 pre-image resistance is algorithmic. The spec does not add
a salt to the `original_hash` computation (Section 2.11.1). The pre-image attack
is feasible for low-entropy values specifically because there is no salt.
**Protocol gap:** no salted hash for `original_hash`. This is an acknowledged
open question (see Section 5).

*Residual risk.* Low-entropy redacted values (phone numbers, SSNs, short codes)
are recoverable by a motivated attacker with the redacted receipt and sufficient
compute. Operators should not rely on redaction markers alone for values with less
than 80 bits of entropy.

---

**Scenario I-4: Approval token leakage via logs or stderr capture**

*Description.* Escalation approval tokens (HMAC-SHA256 hex strings) are
delivered to the approver via stderr or webhook. If the stderr stream is captured
in a log or the webhook delivery is logged by an intermediate proxy, the token
may be accessible to unauthorized parties. A captured token can be used to
approve the specific pending escalation.

*Affected assets.* Constitution approval chain (Section 2.5).

*Mitigation.* Tokens are one-time use (spec Section 8.3): once consumed, the
pending escalation record is removed and the token cannot be reused. The HMAC
binding limits each token to a specific tool call, escalation ID, and timestamp.
The token lifetime is configurable (spec Section 12.5, SHOULD have TTL) -- expired
tokens MUST NOT be accepted. **Protocol-mandated:** HMAC binding and one-time use
(Section 8.3). **Implementation-mandated:** TTL enforcement and escalation store
cleanup.

*Residual risk.* A captured token is usable within its TTL window for the specific
escalation it was issued for. The one-time-use and HMAC binding constraints limit
the blast radius but do not eliminate the risk.

---

**Scenario I-5: Public key fingerprint correlation across deployments**

*Description.* The `key_id` in `receipt_signature` and `constitution_ref` is the
SHA-256 of the raw Ed25519 public key (spec Section 5.6). A fixed key_id across
many receipts allows a passive observer to correlate all receipts from the same
signer, even if the content is otherwise anonymized.

*Affected assets.* Receipt integrity (Section 2.1), signing keypairs (Section
2.2).

*Mitigation.* The correlation is inherent to signed artifact protocols. Key
rotation (spec Section 12.4) changes the key_id. Per-deployment keypairs limit
correlation scope. **Operational.**

*Residual risk.* Correlation is possible within the lifetime of a keypair. This
is a privacy concern, not a security vulnerability -- the key_id is a public
identifier by design.

---

### 3.5 Denial of Service

Denial of service attacks exhaust resources or make a system unavailable. In the
receipt protocol, the primary DoS surfaces are: resource exhaustion via large
fields that participate in hash computation, ReDoS via malicious regex patterns in
constitutions, and verifier exhaustion via deeply nested structures. Many of these
surfaces are controlled by the agent (untrusted), making them relevant threat
vectors.

**Scenario D-1: ReDoS in constitution invariant patterns (H-SCHEMA-5)**

*Description.* Constitution invariant `pattern` fields and `cli_permissions`
`argv_pattern` fields accept arbitrary regex strings. A malicious or
poorly-written pattern with catastrophic backtracking (e.g., `(a+)+$` against a
long non-matching string) can cause the governance runtime to spin for seconds or
minutes per receipt evaluation. An attacker who can influence the constitution
(or who operates a compromised gateway) can deploy such patterns.

This is finding H-SCHEMA-5 from the automated audit (Anthropic Claude) against
v1.2. Status: **OPEN** against v1.5 -- the schema does not constrain pattern
content, and the spec does not require linear-time matchers.

*Affected assets.* Receipt generation availability.

*Mitigation.* The spec does not mandate linear-time regex matching engines.
**Implementation-mandated:** SDK implementations SHOULD use linear-time matchers
(DFA-based) or apply input length limits before pattern evaluation. Mitigation is
not currently normative.

*Residual risk.* A deployment using a regex engine subject to catastrophic
backtracking (PCRE without limits, Python `re` on adversarial input) is
vulnerable. The threat is partially mitigated by the fact that constitutions are
signed -- an attacker cannot inject a malicious pattern at runtime without
breaking the constitution signature. The threat is real if the constitution author
accidentally writes a backtracking pattern.

---

**Scenario D-2: Large correlation_id hash exhaustion (L-SPEC-2 / H-SCHEMA-3)**

*Description.* `correlation_id` participates as a literal string in the
fingerprint input (field 1, spec Section 4.1). There is no `maxLength` constraint
on `correlation_id` in the current spec or schema. An agent (the untrusted actor)
who controls the correlation_id can submit a multi-megabyte string, causing the
fingerprint computation to hash a very large payload on every receipt.

Finding L-SPEC-2 (schema) and H-SCHEMA-3 (spec) from the automated audit
(Anthropic Claude) against v1.2. Status: **OPEN** against v1.5 -- no maxLength is
present in the current schema or spec.

*Affected assets.* Receipt generation availability.

*Mitigation.* None at the protocol layer. **Implementation-mandated:** SDK
implementations SHOULD enforce a maximum correlation_id length (e.g., 255 or 1024
characters) before fingerprint computation. This is not currently normative.

*Residual risk.* A deployment where the agent controls correlation_id and the SDK
does not enforce a length limit is vulnerable to throughput degradation. Typical
deployments where the Sanna runtime generates correlation_ids are not affected.

---

**Scenario D-3: Large-payload content hash exhaustion**

*Description.* The `context_hash` and `output_hash` fields are SHA-256 hashes of
the canonical JSON of the `inputs` and `outputs` objects respectively (spec
Section 4.1). An agent that produces multi-gigabyte outputs (e.g., embedding
large binary content in tool call arguments) forces the Sanna runtime to
serialize and hash that content on every evaluation.

*Affected assets.* Receipt generation availability.

*Mitigation.* None at the protocol layer. `inputs` and `outputs` allow arbitrary
properties (H-SCHEMA-1 from the automated audit). **Implementation-mandated:**
input size limits at the gateway or middleware boundary before receipt evaluation.
**Not currently normative.**

*Residual risk.* The threat is constrained in practice by MCP transport limits and
LLM context window sizes, but the protocol has no ceiling.

---

**Scenario D-4: Receipt storage exhaustion (no maxItems on checks array)**

*Description.* The `checks` array has no `maxItems` constraint in the current
schema. A receipt with millions of check entries passes schema validation. This
inflates receipt file size and can exhaust storage.

Finding M-SCHEMA-4 from the automated audit (Anthropic Claude) against v1.2.
Status: **OPEN** against v1.5 -- no `maxItems` is present on the checks array.

*Affected assets.* Receipt storage availability.

*Mitigation.* None at the protocol layer. **Implementation-mandated:** SDKs SHOULD
cap the number of check results appended to a receipt. Not currently normative.

*Residual risk.* Low severity in practice because the number of checks is bounded
by the number of invariants in the constitution (which is a signed artifact) and
the five built-in C1-C5 checks. A deployment that allows untrusted invariant
injection is more exposed.

---

**Scenario D-5: Verifier exhaustion via deeply nested constitution policies**

*Description.* Constitution YAML structures (nested `halt_conditions`, deeply
nested authority boundaries) have no depth limit in the schema. A malicious
constitution could be constructed with extremely deep nesting that causes the
verifier (or policy evaluator) to exhaust stack or memory.

*Affected assets.* Verifier availability.

*Mitigation.* Constitution signatures defend against unsigned injection -- a
deeply nested constitution still requires a valid author signature to load.
**Implementation-mandated:** JSON/YAML parsers SHOULD impose depth limits.
**Not currently normative in the protocol.**

*Residual risk.* Limited by the requirement that the constitution be signed.
An attacker who controls the constitution authoring process (compromised author
key) could deploy this, but at that point they have stronger attacks available.

---

### 3.6 Elevation of Privilege

Elevation of privilege attacks gain access or capability beyond what was
authorized. In the receipt protocol, the primary EoP surfaces are: authority
boundary bypass (exceeding can_execute scope via name normalization edge cases),
must_escalate downgrade (causing an escalation-required action to be treated as
allowed), and approval token replay or forgery.

**Scenario E-1: Authority boundary bypass via name normalization edge cases**

*Description.* The authority name normalization algorithm (spec Appendix D)
normalizes tool names before matching against constitution boundaries. Edge cases
in normalization (Unicode NFKC interactions, separatorless fallback, glob
anchoring) might allow a tool name that should match `cannot_execute` to instead
match `can_execute`, allowing an otherwise-blocked action to proceed.

*Affected assets.* Constitution provenance (Section 2.4), audit trail (Section
2.6).

*Mitigation.* The normalization algorithm (Appendix D) was significantly revised
from v1.2 to address the bidirectional substring issue identified as H-SPEC-5 in
the automated audit (Anthropic Claude). **ADDRESSED** from H-SPEC-5 in v1.5:

- Non-glob matching is now exact equality after normalization (not bidirectional
  substring). Spec Appendix D.3, rule 1.
- The separatorless fallback is also exact equality (not substring). D.3, rule 1.
- Glob matching is anchored at both ends -- the entire normalized action string
  must match the pattern. D.3, rule 2.
- 16 normalization test vectors (Appendix D.2) and 21 cross-SDK authority-
  matching vectors (`fixtures/authority-matching-vectors.json`) provide a
  conformance contract.

*Residual risk.* Normalization of adversarial Unicode inputs (combining characters,
homoglyphs, zero-width joiners) not covered by the test vectors remains a
theoretical gap. NFKC normalization handles many such cases; the test vectors do
not exhaustively cover all Unicode edge cases.

---

**Scenario E-2: must_escalate downgrade attack**

*Description.* A tool call that matches a `must_escalate` constitution rule is
treated as `can_execute` by a buggy implementation, causing the action to proceed
without human approval. The agent could craft tool names or arguments designed to
trigger this mismatch.

*Affected assets.* Constitution provenance (Section 2.4), constitution approval
chain (Section 2.5).

*Mitigation.* The authority boundary evaluation order MUST check `cannot_execute`
before `can_execute` and `must_escalate` (the spec defines the evaluation
precedence via constitution fields). The gateway MUST halt on `cannot_execute` and
MUST defer on `must_escalate` before checking `can_execute`. **Protocol-mandated:**
evaluation precedence. **Implementation-mandated:** correct evaluation order.

*Residual risk.* Correct implementation is required. A buggy implementation that
checks can_execute before cannot_execute/must_escalate is vulnerable. The
cross-SDK authority-matching test vectors provide a conformance baseline.

---

**Scenario E-3: Approval token forgery**

*Description.* An attacker attempts to forge an HMAC-SHA256 approval token without
knowing the gateway secret. Forging the token would allow approving an escalation
without human interaction.

*Affected assets.* Constitution approval chain (Section 2.5).

*Mitigation.* HMAC-SHA256 token binding (spec Section 8.2): without the gateway
secret, computing a valid token for a given escalation_id, tool_name,
args_digest, and issued_at is computationally infeasible. The gateway secret is a
per-gateway random bytes value, held in memory or stored in a restricted file
(`~/.sanna/gateway_secret`). **Protocol-mandated:** HMAC-SHA256 binding.

*Residual risk.* If the gateway secret is compromised, all pending escalations
are forgeable. Gateway secret management is operational; the protocol does not
specify key management procedures for the gateway secret beyond noting where it
should be stored.

---

**Scenario E-4: Approval token replay across escalations**

*Description.* A valid approval token is captured (e.g., from logs or network
interception) and replayed to approve a different escalation or the same
escalation a second time.

*Affected assets.* Constitution approval chain (Section 2.5).

*Mitigation.* HMAC token binding (spec Section 8.2): the token encodes
escalation_id, tool_name, args_digest, and issued_at. A token from escalation A
cannot be used for escalation B because the escalation_id will differ. One-time
use (spec Section 8.3): a consumed token cannot be accepted again because the
pending escalation record is removed from the store. TTL (spec Section 12.5
SHOULD have configurable TTL): expired tokens MUST NOT be accepted.
**Protocol-mandated:** HMAC binding and one-time use.

*Residual risk.* Cross-escalation replay is prevented by the HMAC binding. Same-
escalation replay is prevented by one-time use. TTL is SHOULD (not MUST), so
deployments without configured TTL have no time-based expiry as a backstop.

---

**Scenario E-5: SSRF via webhook escalation target (H-SCHEMA-4)**

*Description.* The `must_escalate.target.url` field in the constitution accepts
any string. A constitution (or a malicious modification of a constitution with a
compromised author key) could specify an internal network address (`http://169.254.169.254/`,
`file:///etc/passwd`, `javascript:...`) as the webhook target, causing the gateway
to make requests to internal infrastructure on behalf of the attacker.

This is finding H-SCHEMA-4 from the automated audit (Anthropic Claude) against
v1.2. Status: **PARTIAL** against v1.5.

*Partial mitigation.* Spec Section 12.5 requires: "Webhook escalation targets MUST
validate the destination URL to prevent SSRF. Implementations SHOULD reject private
and internal IP ranges and non-HTTPS URLs." The requirement is normative
(MUST validate) but the schema does not enforce a URL format constraint. The
schema's `url` field is `{"type": ["string", "null"]}` with no `format: "uri"`
or pattern constraint.

*Remaining gap.* Schema does not enforce URL validity or safety. The MUST
requirement in Section 12.5 is implementation-mandated, not schema-enforced.

*Affected assets.* Gateway availability and integrity (potential pivot to internal
network).

*Residual risk.* Depends on implementation correctly applying the Section 12.5
MUST. A deployment using an SDK that does not implement URL validation per Section
12.5 is vulnerable. This is mitigated by the fact that the webhook URL is in the
signed constitution -- the attacker must compromise the author key to inject a
malicious URL into a loaded constitution.

---

**Scenario E-6: Privilege escalation via extension namespace pollution (H-SCHEMA-2)**

*Description.* The `extensions` field is completely unconstrained in the current
schema (no depth limit, no size limit, no key constraints). An agent who can
influence receipt construction could inject extension keys that shadow or confuse
naive verifiers (e.g., injecting a key named `receipt_signature` inside
extensions to confuse a verifier that does not strictly isolate the receipt top
level).

This is finding H-SCHEMA-2 from the automated audit (Anthropic Claude) against
v1.2. Status: **OPEN** against v1.5 -- the schema does not constrain extensions
beyond being an object.

*Affected assets.* Receipt integrity (Section 2.1).

*Mitigation.* Reverse-domain namespacing convention for extension keys (spec
Section 2.20.1 for the `com.sanna.*` namespace). The spec documents the namespace
convention but does not require `additionalProperties: false` at the top level
of the receipt. A compliant verifier processes only documented fields;
extension-namespace pollution affects only verifiers that process extensions
without namespace isolation. **Not protocol-mandated:** extension depth limits or
maximum payload sizes.

*Residual risk.* Verifiers that process `extensions` without namespace isolation
are exposed. The com.sanna.manifest and com.sanna.anomaly extension namespaces
have defined schemas (spec Sections 2.20 and 2.22) but their enforcement is
implementation-mandated.

---

## 4. Mitigations

### 4.1 Protocol-Mandated Mitigations

The following mitigations are required (MUST/SHALL/REQUIRED) by the current v1.5
specification. An implementation that omits any of these is non-conformant.

| Mitigation | Spec Section | Category |
|------------|-------------|----------|
| Ed25519 Pure signature (no prehash, no context) on receipt signing | 5.1, 5.2 | Integrity |
| Fingerprint construction: pipe-delimited SHA-256 over cv-dispatched field list | 4.1 | Integrity |
| Canonical JSON (RFC8785-style sorted keys, no spaces) for fingerprint and signing | 3.1 | Determinism |
| hash_text() NFC normalization + line-end + whitespace strip before SHA-256 | 3.3 | Determinism |
| HMAC-SHA256 token binding for escalation approvals (specific tool + escalation_id + args + timestamp) | 8.2 | Non-repudiation |
| One-time use of escalation tokens (remove after resolution) | 8.3 | Non-repudiation |
| NFC normalization for hash_text inputs | 3.3 | Cross-SDK parity |
| Authority name normalization: NFKC + camelCase split + separator norm + casefold + dot-join | Appendix D.1 | Authority enforcement |
| Non-glob match: exact equality after normalization (not substring) | Appendix D.3 | Authority enforcement |
| Glob match: anchored at both ends, only * is metachar | Appendix D.3 | Authority enforcement |
| enforcement_surface field inclusion in fingerprint (cv >= 8, field 15) | 2.16, 4.1 | Provenance |
| tool_name field inclusion in fingerprint (cv >= 9, field 17) | 2.17, 4.1 | Provenance |
| Status/enforcement cross-field consistency check (error on mismatch) | 4.6 | Integrity |
| SSRF validation for webhook escalation targets (MUST validate) | 12.5 | Network safety |
| Pre-existing marker injection guard for redaction markers | 2.11.4 | Injection defense |
| Trust anchor warning banner when SANNA_TRUSTED_KEY_IDS not supplied | 10.1 | Verifier hygiene |
| Webhook token lifetime: expired tokens MUST NOT be accepted | 12.5 | Token security |
| Per-role keypair separation (RECOMMENDED, not MUST) | 12.4 | Key management |

### 4.2 Implementation-Mandated Mitigations

The following mitigations are not fully specified by the protocol but are required
or strongly implied for a secure deployment. The protocol may state SHOULD or
leave them as implementation responsibility.

| Mitigation | Basis | Notes |
|------------|-------|-------|
| Private key file permissions 0o600 or equivalent | Spec Section 12.4 | Operational; not schema-enforced |
| Trust anchor establishment (supply SANNA_TRUSTED_KEY_IDS) | Spec Section 10.1 | Operator responsibility; protocol warns but does not block |
| Linear-time regex matching for constitution invariant patterns | H-SCHEMA-5 (OPEN) | Not normative; SHOULD be enforced by SDK |
| Input size limits (correlation_id, inputs, outputs) before hash computation | H-SCHEMA-3 (OPEN) | Not normative; SHOULD be enforced by SDK |
| Escalation token TTL enforcement | Spec Section 12.5 (SHOULD) | SHOULD is not MUST; recommended default <= 1 hour |
| Escalation store cleanup on TTL expiry | Spec Section 12.5 | Implementation-internal |
| Gateway secret management (random bytes, restricted storage) | Spec Section 8.2 | Operational; not in schema |
| Webhook URL validation (reject private IPs, non-HTTPS) | Spec Section 12.5 (MUST) | MUST in spec text; schema does not enforce |
| JSON/YAML depth limits for constitution loading | DoS (Section 3.5) | Not normative |
| TLS certificate validation for webhook delivery | Spec Section 12.5 (SHOULD) | Not yet normative |
| Extension namespace isolation in verifier processing | H-SCHEMA-2 (OPEN) | Not normative |
| Append-only storage for receipt audit trail | XC-1 | Cloud implementation responsibility; not in protocol |
| checks array size limit in SDK | M-SCHEMA-4 (OPEN) | Not normative |
| Key ID dynamic resolution from golden fixtures (not hardcoded) | SECURITY.md SAN-404 | Test key rotation pattern |

### 4.3 Explicitly Out of Scope

The following attack surfaces are explicitly NOT defended against by the Sanna
protocol. Acknowledging these limits is part of an honest threat model.

**Compromised endpoint platform or OS-level compromise.** If the operating system
or host process memory is compromised, the Sanna runtime can be modified to forge
receipts, skip governance checks, or exfiltrate signing keys. Sanna assumes a
trusted runtime environment.

**Compromised Sanna library binary (supply-chain attack).** If the sanna or
@sanna/core package itself is malicious or tampered, all governance guarantees
are void. Sanna does not self-verify its own integrity. Dependency supply-chain
security is the operator's responsibility (audited packages, pinned versions,
lockfiles with hashes).

**Stolen signing keys.** Key management is operational. The protocol recommends
per-role keypairs and file permissions (Section 12.4) but cannot prevent physical
or logical access to key files. Stolen keys enable arbitrary forgery.

**Bypassing Sanna entirely.** If the agent or its tools are not in the Sanna
gateway or middleware execution path, no receipt is generated. Sanna is an
observational system, not a process isolation boundary. Deployment architecture
must ensure the Sanna runtime is in the critical path.

**Semantic completeness of governance checks.** The built-in C1-C5 checks are
heuristic pattern matchers (LLM-evaluated). They catch common reasoning failures
but do not provide formal verification of agent behavior. A determined agent may
produce outputs that pass C1-C5 while violating the intended governance policy.

**Downstream execution fidelity at the gateway boundary.** The gateway attests to
what tool call arguments it forwarded, not what the downstream tool server
actually executed with those arguments. The tool server may behave differently
than expected even when the forwarded arguments are identical to what was
governed.

**Hardware attacks.** Side-channel attacks on the signing key during Ed25519
computation, fault injection during canonicalization, or physical access to the
host are out of scope.

**Receipt storage encryption at rest.** The protocol does not specify encryption
of stored receipts. PII redaction (Section 2.11) addresses content sensitivity
but receipt files at rest are not encrypted by the protocol.

---

## 5. Open Questions

This section itemizes unresolved threats or design questions explicitly deferred
to future spec versions. Each item has been verified against the current v1.5 spec
text; items already fully addressed by v1.5 are not listed.

**OQ-1: Post-quantum signature migration path.**

*Question.* What is the migration strategy when Ed25519 becomes vulnerable to
quantum attack?

*Why open.* Ed25519 is not PQ-safe (Shor's algorithm applied to elliptic-curve
discrete logarithm). While quantum computers capable of running Shor's algorithm
at scale do not exist as of this document's date, the migration path for receipts
signed under Ed25519 (including historical receipts that need to remain
verifiable) has not been specified.

*Tracking.* Not yet filed as a Sanna ticket as of this document.

---

**OQ-2: Salted redaction marker hashes.**

*Question.* Should `original_hash` in redaction markers include a per-receipt or
per-deployment salt to prevent rainbow-table attacks on low-entropy values?

*Why open.* The current computation (SHA-256 of NFC-normalized value, no salt,
Section 2.11.1) is vulnerable to pre-image attacks for low-entropy values such as
phone numbers or short identifiers. Adding a salt would require specifying how the
salt is derived, stored, and distributed to authorized auditors.

*Tracking.* Not yet filed as a Sanna ticket as of this document.

---

**OQ-3: Verifier-side replay detection (no receipt nonce or sequence number).**

*Question.* Should the receipt format include a nonce or monotonic sequence number
to allow verifiers to detect replayed receipts?

*Why open.* Receipts do not include a nonce or sequence number. A signed receipt
can be replayed to a verifier that has already seen it; without external state,
the verifier cannot distinguish a replay from a legitimate re-submission. For
append-only audit databases, replay detection is handled at the ingestion layer;
for offline verifiers, there is no mechanism.

*Tracking.* Not yet filed as a Sanna ticket as of this document.

---

**OQ-4: Constitution rotation while preserving receipt verifiability.**

*Question.* When a constitution is re-signed with a new author keypair (key
rotation), how should existing receipts (whose `constitution_ref` references the
old `policy_hash` and old signature) continue to be verifiable?

*Why open.* The spec specifies key rotation (Section 12.4) at a high level ("Old
receipts remain verifiable against the old public key") but does not specify how
verifiers should maintain or distribute historical public key material. An
evidence bundle verifier must find the correct public key for a receipt signed
under a retired keypair.

*Tracking.* Not yet filed as a Sanna ticket as of this document.

---

**OQ-5: Unsigned receipt conformance level signaling.**

*Question.* Should the protocol define explicit conformance levels (e.g.,
`signed/tamper-evident`, `unsigned/audit-only`) and require receipts to declare
which level they assert?

*Why open.* Multiple findings in the automated audit (Anthropic Claude,
2026-03-26 -- XC-1, C-SPEC-1, H-SPEC-2, M-SPEC-2) compound on unsigned receipts.
The current spec allows unsigned receipts as a valid conformance target but
provides no mechanism for verifiers to signal that an unsigned receipt is
insufficient for a given assurance level. Conformance level declaration would
allow downstream consumers to reject unsigned receipts in high-assurance contexts.

*Tracking.* Not yet filed as a Sanna ticket as of this document.

---

**OQ-6: C-SCHEMA-1 -- receipt_signature object required fields.**

*Question.* Should the receipt schema require `signature`, `key_id`, and `scheme`
when the `receipt_signature` object is present (non-null)?

*Why open.* The current schema does not mark any field within `receipt_signature`
as required (verified against `schemas/receipt.schema.json`). A receipt with
`"receipt_signature": {}` passes schema validation, presenting a false sense of
cryptographic assurance. This is finding C-SCHEMA-1 from the automated audit
(Anthropic Claude), status **OPEN** against v1.5.

*Tracking.* Not yet filed as a Sanna ticket as of this document.

---

**OQ-7: Enforcement elevation for FAIL receipts with null enforcement.**

*Question.* Should the verification protocol elevate step 6 ("FAIL + no
enforcement" is currently warning-only per spec Section 9.1) to a verification
error rather than a warning?

*Why open.* A FAIL receipt with `enforcement: null` passes verification with only
a warning (exit code 0) in the current protocol (finding C-SPEC-2, status
**PARTIAL** in v1.5 -- Section 4.6 helps when enforcement is present, but step 6
remains warning-only when enforcement is null). Applications that treat a
warning-level receipt as proof of governance enforcement are misled.

*Tracking.* Not yet filed as a Sanna ticket as of this document.

---

**OQ-8: maxLength for correlation_id and maxItems for checks array.**

*Question.* Should the schema add `maxLength` to `correlation_id` and `maxItems`
to the `checks` array to prevent resource exhaustion?

*Why open.* Both fields have no upper bound in the current schema (verified
against `schemas/receipt.schema.json`). Findings H-SCHEMA-3, L-SPEC-2, and
M-SCHEMA-4 from the automated audit (Anthropic Claude) are all **OPEN** against
v1.5.

*Tracking.* Not yet filed as a Sanna ticket as of this document.

---

## 6. References

| Reference | Path / Citation |
|-----------|----------------|
| Sanna Specification v1.5 | `spec/sanna-specification-v1.5.md` |
| Sanna Protocol Architecture | `docs/architecture.md` |
| Security Audit (automated, Anthropic Claude, 2026-03-26) | `security-audit-sanna-protocol-2026-03-26.md` |
| Sanna Security Policy | `SECURITY.md` |
| RFC8032 -- Edwards-Curve Digital Signature Algorithm (EdDSA) | IETF RFC8032 |
| RFC8785 -- JSON Canonicalization Scheme (JCS) | IETF RFC8785 |
| RFC4648 -- Base64 Data Encoding | IETF RFC4648 |
| RFC2119 -- Key words for use in RFCs | IETF RFC2119 |
| UAX #15 -- Unicode Normalization Forms | Unicode Standard Annex 15 |
| STRIDE methodology | Microsoft Security Development Lifecycle |
