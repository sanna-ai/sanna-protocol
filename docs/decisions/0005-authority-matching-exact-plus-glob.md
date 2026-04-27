# ADR-0005: Authority Matching — Exact + Opt-In Glob (Rejected: Substring)

## Status

Accepted

## Date

2026-04-22

## Context

A constitution's `authority_boundaries` block specifies patterns (e.g., `cannot_execute: ["read"]`) that are matched against tool-call action names at enforcement time. The Python SDK and spec Appendix D used substring matching; the TypeScript SDK used exact match + opt-in glob.

Consequence: the pattern `"read"` matched action `"bread"` in Python (substring hit) but not in TypeScript (no substring, no glob). A constitution intending to block `read` calls would halt in Python and allow in TypeScript for the same action — governance decisions diverged by SDK. This broke the core governance-portability claim: a constitution should produce identical decisions regardless of which SDK is running the agent.

Evidence from SAN-224 (Codex review finding F-005):
- `sanna-protocol/spec/sanna-specification-v1.3.md:1775–1785` — Appendix D specified substring.
- `sanna-repo/src/sanna/enforcement/authority.py:248` — Python: `if pattern in action_name`.
- `sanna-ts/packages/core/src/evaluator.ts:66` — TypeScript: exact + opt-in glob.

Repro: Python `_matches_action("read", "bread")` = `True`; TypeScript `evaluateAuthority("bread", {cannot_execute:["read"]})` = allowed.

## Decision

Authority matching uses **exact match + opt-in glob** only. Substring matching is explicitly disallowed.

**Exact match**: normalized action name equals normalized pattern. Both sides undergo NFKC + camelCase split + separator normalization + casefold before comparison.

**Opt-in glob**: if the pattern contains `*`, the match uses glob semantics. Glob rules:
- Only `*` is a wildcard. No `?`, `[`, `]`, `{`, `}`.
- Anchored full-match (pattern must match the entire normalized action name, not a substring of it).
- `**` is treated as a single `*` (no directory-traversal semantics).

If the pattern contains no `*`, exact equality (post-normalization) is the only match path. There is no separatorless-fallback to substring.

Cross-SDK contract enforcement: `fixtures/authority-matching-vectors.json` (21 vectors, 7 categories: exact/normalize/glob/regex-rejected/substring-rejected/delimiter/edge) is loaded by parametrized tests in both SDKs' CI. A passing CI in both SDKs is the normative proof of parity.

## Alternatives Considered

- **Keep substring matching (match Python to spec).** Rejected: governance portability is broken. A constitution cannot be ported between SDKs with confidence. F-005 demonstrated the divergence with a concrete repro case. Substring matching also allows unintentional over-broad governance: a pattern `"read"` accidentally governing `"thread"`, `"spread"`, etc.
- **Full glob or regex (fnmatch or re).** Rejected: introduces ReDoS risk. Unbounded backtracking on adversarial inputs is a security concern for a trust-infrastructure product. The opt-in glob subset is closed under the attack surface.
- **Make TS match Python (add substring to TS).** Rejected: TypeScript's behavior was correct. Python and spec were converged onto TypeScript's implementation, not the reverse.

## Consequences

- Cross-SDK byte-parity in authority decisions is now CI-enforced via the shared 21-vector fixture.
- Constitutions port cleanly between Python and TypeScript SDKs.
- F-005 repro case (`"read"` matching `"bread"`) explicitly returns false in both SDKs and is in the fixture set.
- Existing constitutions using substring-dependent patterns (e.g., `"read"` to govern all read-family tools) require migration to explicit glob patterns (`"read*"` or `"*read*"` as appropriate). Migration guidance in Python CHANGELOG.
- SAN-242 tracks restoration of sanna-protocol as a git submodule in sanna-repo (fixture was file-copied during SAN-224 execution).

## References

- SAN-224 (Authority matching: converge on exact + explicit-glob across SDKs)
- `fixtures/authority-matching-vectors.json` (21-vector cross-SDK contract fixture)
- Spec `sanna-specification-v1.4.md` Appendix D §D.3–D.5
- `sanna-repo/src/sanna/enforcement/authority.py` (`_matches_action` implementation)
- `sanna-ts/packages/core/src/evaluator.ts` (`matchesAction` implementation)
- SAN-242 (submodule restoration, Backlog)
