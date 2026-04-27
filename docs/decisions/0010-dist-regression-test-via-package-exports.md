# ADR-0010: Dist Regression Test Discipline — Test Through Package-Exports, Not src

## Status

Accepted

## Date

2026-04-21 (SAN-220); extended 2026-04-23 (SAN-221)

## Context

SAN-220 discovered that the `@sanna-ai/core` dist artifact was 2+ days stale at the time of the Codex review (finding F-001). The dist still contained the pre-SAN-213 HALT bug at `dist/index.js:4963,5701` and lacked the 4-action enforcement override. Source (`src/receipt.ts:335`) was correct. All existing tests ran against `src`; none imported through the package's `exports` field (`"." → "./dist/index.js"`).

Consequence: runtime consumers importing `@sanna-ai/core` through npm — which always imports from `dist` — could generate a receipt with `status="PASS"` and `enforcement.action="halted"`, and `verifyReceipt()` from `dist` would return valid. Receipt forgery by semantic inconsistency. CI gave no signal.

SAN-221 (finding F-002) confirmed a second gap: the dist verifier did not enforce v1.3 required fields or emit v1.3 legacy warnings, even after SAN-213's source-level fix.

The root failure mode: source tests and dist are different artifacts. CI can be green on source while dist is broken. This class of failure is silent until a downstream consumer hits it.

## Decision

TypeScript packages that publish a `dist` artifact via an `exports` field MUST have at least one regression test file that imports the package through its `exports` field (the dist path), not from `src` or via relative imports.

**Canonical file**: `packages/core/tests/dist-regression.test.ts`

The test file imports `@sanna-ai/core` (the package name, resolved through `exports` to `dist/index.js`), not `../../src/receipt.ts` or similar. Any dist staleness or bundler regression in covered paths causes CI failure at PR time.

**Minimum coverage for `@sanna-ai/core` dist-regression.test.ts** (12 assertions at SAN-221 close):
- v1.4 constants (SPEC_VERSION, CHECKS_VERSION, TOOL_NAME, TOOL_VERSION bare semver).
- 4-action enforcement override for all 4 action values via dist emitter.
- cv=9 required-field verifier check via dist verifier.
- cv=8 missing `enforcement_surface` → hard error (exact string match, not substring).
- cv=8 missing `invariants_scope` → hard error (exact string match).
- cv=6 missing both v1.3 fields → two legacy warnings (byte-exact parity with Python verifier output).
- cv=7 missing `invariants_scope` → asymmetric legacy warning.

Error string assertions use `.toContain(array, exactElement)` (not `.includes()`) for byte-exact cross-SDK parity enforcement.

## Alternatives Considered

- **Trust source tests only.** Rejected: SAN-220 proved this fails. Source green, dist broken, downstream consumers hit the bug. The gap between "tests pass" and "published package is correct" is a governance risk for trust infrastructure.
- **Manual dist verification before each PR.** Rejected: drift is inevitable. Manual steps fail under time pressure, are not enforced by CI, and were already failing at SAN-220 discovery time.
- **Commit dist to the repo.** Rejected: bloats git history with generated artifacts, creates merge conflicts on dist, and does not eliminate the staleness problem (a committed dist can still be stale relative to src).
- **Snapshot testing on dist output.** Rejected: snapshot tests catch changes but require manual update on every intentional change, creating friction and "update the snapshot" false-positive patterns.

## Consequences

- Any future bundler regression or source-to-dist divergence in covered paths fails CI at PR time, not at downstream consumer discovery time.
- `packages/core/tests/dist-regression.test.ts` is the canonical example for other dist-publishing packages in the monorepo. Pattern propagates to `@sanna-ai/cli`, `@sanna-ai/gateway`, `@sanna-ai/mcp-server` as they grow.
- The test requires a built dist to exist; CI must run `npm run build` before `vitest`. This is a standard constraint for publication-readiness CI.
- Test count baseline: 1070/1070 passing post-SAN-220 (net +8); 1111/1111 post-SAN-221 (net +41 since SAN-220 baseline).
- F-001-class gap (dist semantic staleness) is permanently closed for `@sanna-ai/core`.

## References

- SAN-220 (TS: rebuild @sanna-ai/core dist to include v1.3 enforcement override — root cause + resolution)
- SAN-221 (TS: verify dist verifier emits v1.3 required-field errors and legacy warnings — CI assertion gap)
- SAN-239 (Minimum-viable CI across non-Python repos — CI workflow wiring for this test)
- `sanna-ts/packages/core/tests/dist-regression.test.ts`
- `sanna-ts/packages/core/package.json` (exports field pointing at dist)
