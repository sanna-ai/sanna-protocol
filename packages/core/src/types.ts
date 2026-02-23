/**
 * Sanna Protocol — shared type definitions.
 */

// ── Constitution types ───────────────────────────────────────────────

export interface Boundary {
  id: string;
  description: string;
  category: "scope" | "authorization" | "confidentiality" | "safety" | "compliance" | "custom";
  severity: "critical" | "high" | "medium" | "low" | "info";
}

export interface HaltCondition {
  id: string;
  trigger: string;
  escalate_to: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  enforcement: "halt" | "warn" | "log";
}

export interface TrustTiers {
  autonomous: string[];
  requires_approval: string[];
  prohibited: string[];
}

export interface TrustedSources {
  tier_1: string[];
  tier_2: string[];
  tier_3: string[];
  untrusted: string[];
}

export interface ConstitutionSignature {
  value: string | null;
  key_id: string | null;
  signed_by: string | null;
  signed_at: string | null;
  scheme: string;
}

export interface Provenance {
  authored_by: string;
  approved_by: string[];
  approval_date: string;
  approval_method: string;
  change_history: Record<string, string>[];
  signature: ConstitutionSignature | null;
}

export interface AgentIdentity {
  agent_name: string;
  domain: string;
  description: string;
  extensions: Record<string, unknown>;
}

export interface Invariant {
  id: string;
  rule: string;
  enforcement: "halt" | "warn" | "log";
  check: string | null;
}

export interface EscalationTargetConfig {
  type: "log" | "webhook" | "callback";
  url?: string;
  handler?: string;
}

export interface EscalationRule {
  condition: string;
  target: EscalationTargetConfig | null;
}

export interface AuthorityBoundaries {
  cannot_execute: string[];
  must_escalate: EscalationRule[];
  can_execute: string[];
  default_escalation: string;
}

export interface Constitution {
  schema_version: string;
  identity: AgentIdentity;
  provenance: Provenance;
  boundaries: Boundary[];
  trust_tiers: TrustTiers;
  halt_conditions: HaltCondition[];
  invariants: Invariant[];
  policy_hash: string | null;
  authority_boundaries: AuthorityBoundaries | null;
  trusted_sources: TrustedSources | null;
}

// ── Authority evaluation types ───────────────────────────────────────

export type AuthorityDecisionType = "halt" | "allow" | "escalate";
export type BoundaryType = "cannot_execute" | "must_escalate" | "can_execute" | "uncategorized";

export interface AuthorityDecision {
  decision: AuthorityDecisionType;
  reason: string;
  boundary_type: BoundaryType;
}

// ── Receipt types ────────────────────────────────────────────────────

export interface CheckResult {
  check_id: string;
  name?: string;
  passed: boolean;
  severity: string;
  evidence: string | null;
  details?: string;
  status?: string;
  triggered_by?: string | null;
  enforcement_level?: string | null;
  check_impl?: string | null;
  replayable?: boolean | null;
}

export interface ReceiptSignature {
  signature: string;
  key_id: string;
  signed_by: string;
  signed_at: string;
  scheme: string;
}

export interface Enforcement {
  action: string;
  reason: string;
  failed_checks: string[];
  enforcement_mode: string;
  timestamp: string;
}

export interface ConstitutionRef {
  document_id: string;
  policy_hash: string;
  version?: string;
  source?: string;
  approved_by?: string | string[];
  approval_date?: string;
  approval_method?: string;
  signature_verified?: boolean;
  scheme?: string;
  constitution_approval?: unknown;
}

/** A full Sanna receipt (signed or unsigned). */
export interface Receipt {
  spec_version: string;
  tool_version: string;
  checks_version: string;
  receipt_id: string;
  receipt_fingerprint: string;
  full_fingerprint: string;
  correlation_id: string;
  timestamp: string;
  inputs: Record<string, unknown>;
  outputs: Record<string, unknown>;
  context_hash: string;
  output_hash: string;
  checks: CheckResult[];
  checks_passed: number;
  checks_failed: number;
  status: string;
  receipt_signature?: ReceiptSignature;
  constitution_ref?: ConstitutionRef;
  enforcement?: Enforcement;
  evaluation_coverage?: Record<string, unknown>;
  authority_decisions?: Record<string, unknown>[];
  escalation_events?: Record<string, unknown>[];
  source_trust_evaluations?: Record<string, unknown>[];
  extensions?: Record<string, unknown>;
  identity_verification?: Record<string, unknown>;
  [key: string]: unknown;
}

// ── Verification types ───────────────────────────────────────────────

export interface VerificationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  checks_performed: string[];
}
