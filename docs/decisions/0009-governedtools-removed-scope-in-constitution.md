# ADR-0009: governedTools Removed; Per-Tool Governance Scope (If Reintroduced) Lives in the Constitution

## Status

Accepted

## Date

2026-04-26

## Context

`sanna-openclaw` exposed a `governedTools` configuration option with documentation describing three tiers of per-tool governance scope. The config field was defined in `src/config.ts`, defaults were in `DEFAULT_CONFIG`, and it appeared in the `openclaw.plugin.json` schema, README, and docs/SETUP.md.

SAN-231 discovery found that `src/hooks.ts` never consulted `config.governedTools` before evaluating tool calls. The `before_tool_call` hook evaluated authority on every tool call unconditionally. `governedTools` appeared only at `cli.ts:49` (status display) and `gateway.ts:47` (sanna.status RPC response) — purely display-only, with no enforcement effect.

The governance consequence: documentation and config implied that operators could configure which tools Sanna governs, but the implementation governed all tools regardless. This is a documentation/config drift, but the gap points to a deeper governance question. Enforcing `governedTools` as documented (Option A) would allow local config to opt tools out of governance — a silent safety downgrade. An operator modifying their local OpenClaw config could exempt specific tools from the Sanna governance loop without any approval-workflow record.

## Decision

`governedTools` removed. Everything-governed-by-default is the model.

The safer code behavior (govern all tools) is retained and docs are updated to match. When code and docs disagree on a safety knob, fix docs to match the safer code.

If per-tool governance scope is needed in the future, it MUST live in the **constitution** as a `governance_scope` field, not in local config. Governance-correct shape (filed in SAN-322):

```
governance_scope: {
  mode: "default" | "include" | "exclude",
  include: [...],  # if mode == "include"
  exclude: [...],  # if mode == "exclude"
}
```

Why constitution, not local config:
- Constitution changes go through the approval workflow, producing a receipt proving the scope change was authorized.
- The receipt's `policy_hash` cryptographically proves which scope was active when each tool ran.
- `invariants_scope` vocabulary at the receipt level already encodes the enforcement result.
- Operations teams cannot unilaterally reduce governance coverage without an auditable approval record.

## Alternatives Considered

- **Enforce `governedTools` at the hook layer (Option A).** Rejected: allows local config to silently reduce governance coverage. An operator could exempt high-risk tools from governance by editing a local JSON file, with no approval-workflow record and no receipt-level proof of the scope change.
- **Leave `governedTools` undocumented and unused.** Rejected: documentation drift is itself a governance problem. Operators reading the docs would believe they can configure per-tool scope and be wrong. Wrong documentation for a safety knob is worse than no documentation.
- **Add enforcement but require constitution override to bypass.** Equivalent to the chosen direction; the chosen approach is cleaner because it starts from the correct default (govern everything) and adds selective scope via constitution when needed.

## Consequences

- `governedTools` removed from `src/types.ts`, `src/config.ts`, `openclaw.plugin.json`, README, SETUP.md, and 5 test files. Suite: 216/216 after removal (was 223; 7 `governedTools`-specific test cases removed).
- Per-tool scope (if and when a customer needs it) requires a constitution change, giving it approval-workflow coverage and receipt-level proof.
- SAN-322 holds the governance-correct constitution field design for when that need surfaces.
- Simpler config surface: no knob that appears to configure governance but does not.

## References

- SAN-231 (OpenClaw: enforce governedTools config or remove from docs — Option B chosen)
- SAN-322 (Per-tool governance scope as constitution field — filed forward)
- ADR-0003 (status derivation — governs all tool calls; per-tool scope would modify invariants_scope on the receipt)
- `sanna-openclaw/CHANGELOG.md` (v1.1.0 entry recording the removal and migration note)
- `sanna-openclaw/src/hooks.ts` (`before_tool_call` — governs unconditionally)
