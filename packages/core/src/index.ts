// @sanna/core — Sanna protocol SDK

export {
  EMPTY_HASH,
  canonicalize,
  hashBytes,
  hashContent,
  hashObj,
} from "./hashing.js";

export {
  generateKeypair,
  sign,
  verify,
  loadPrivateKey,
  loadPublicKey,
  getKeyId,
  exportPrivateKeyPem,
  exportPublicKeyPem,
} from "./crypto.js";

export type { SannaKeypair, KeyObject } from "./crypto.js";

export {
  loadConstitution,
  parseConstitution,
  validateConstitutionData,
  verifyConstitutionSignature,
  computeFileContentHash,
} from "./constitution.js";

export {
  evaluateAuthority,
  normalizeAuthorityName,
} from "./evaluator.js";

export {
  generateReceipt,
  signReceipt,
  computeFingerprints,
  computeFingerprintInput,
  SPEC_VERSION,
  CHECKS_VERSION,
} from "./receipt.js";

export type { ReceiptParams } from "./receipt.js";

export { verifyReceipt } from "./verifier.js";

export type {
  Constitution,
  Boundary,
  HaltCondition,
  TrustTiers,
  TrustedSources,
  ConstitutionSignature,
  Provenance,
  AgentIdentity,
  Invariant,
  EscalationTargetConfig,
  EscalationRule,
  AuthorityBoundaries,
  AuthorityDecision,
  AuthorityDecisionType,
  BoundaryType,
  Receipt,
  CheckResult,
  ReceiptSignature,
  Enforcement,
  ConstitutionRef,
  VerificationResult,
} from "./types.js";
