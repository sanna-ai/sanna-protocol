/**
 * Sanna Protocol — C1-C5 Coherence Checks
 *
 * Structural heuristic checks modeled after the Python receipt.py C1-C5.
 * These are keyword/pattern-based (not LLM-based).
 *
 * C1: Context Grounding — does the output reference the provided context?
 * C2: Constitutional Alignment — does the output respect constitution constraints?
 * C3: Instruction Adherence — does the output follow the query/instruction?
 * C4: Output Consistency — always passes (structural only)
 * C5: Constraint Satisfaction — are length/format constraints met?
 */

import type { CheckResult, Constitution } from "./types.js";

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * Extract significant keywords (3+ chars, non-stop) from text.
 */
const STOP_WORDS = new Set([
  "a", "an", "the", "and", "or", "but", "for", "nor", "so", "yet",
  "in", "on", "at", "to", "of", "by", "is", "it", "as", "if",
  "be", "do", "no", "not", "are", "was", "were", "has", "had",
  "with", "from", "into", "that", "this", "than", "can", "may",
  "will", "its", "all", "any", "our", "your", "their", "which",
  "what", "when", "where", "who", "how", "why", "would", "should",
  "could", "have", "been", "being", "each", "more", "some", "such",
  "they", "them", "then", "these", "those", "other", "about",
]);

function extractKeywords(text: string): string[] {
  const words = text.toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/);
  return [...new Set(words.filter((w) => w.length >= 3 && !STOP_WORDS.has(w)))];
}

// ── C1: Context Grounding ────────────────────────────────────────────

export interface CoherenceCheckOptions {
  context?: string;
  query?: string;
  output: string;
  constitution?: Constitution;
}

/**
 * C1: Context Grounding — does the output reference the provided context?
 *
 * Structural check: extracts significant keywords from the context and
 * verifies that a minimum fraction appear in the output. When no context
 * is provided, passes with an "info" note.
 */
export function checkC1ContextGrounding(opts: CoherenceCheckOptions): CheckResult {
  const { context, output } = opts;

  if (!context || !context.trim()) {
    return {
      check_id: "C1",
      name: "Context Grounding",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No context provided — grounding check skipped",
    };
  }

  if (!output || !output.trim()) {
    return {
      check_id: "C1",
      name: "Context Grounding",
      passed: false,
      severity: "high",
      evidence: "Output is empty but context was provided",
      details: "Empty output cannot reference context",
    };
  }

  const contextKeywords = extractKeywords(context);
  if (contextKeywords.length === 0) {
    return {
      check_id: "C1",
      name: "Context Grounding",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No significant keywords in context",
    };
  }

  const outputLower = output.toLowerCase();
  const matched = contextKeywords.filter((kw) => outputLower.includes(kw));
  const ratio = matched.length / contextKeywords.length;

  // Require at least 10% of context keywords to appear in output
  if (ratio < 0.1 && contextKeywords.length >= 3) {
    return {
      check_id: "C1",
      name: "Context Grounding",
      passed: false,
      severity: "high",
      evidence: `Only ${matched.length}/${contextKeywords.length} context keywords found in output (${(ratio * 100).toFixed(0)}%)`,
      details: "Output does not appear to reference the provided context",
    };
  }

  return {
    check_id: "C1",
    name: "Context Grounding",
    passed: true,
    severity: "info",
    evidence: null,
    details: `${matched.length}/${contextKeywords.length} context keywords found in output`,
  };
}

// ── C2: Constitutional Alignment ─────────────────────────────────────

/**
 * C2: Constitutional Alignment — does the output respect constitution constraints?
 *
 * Structural check: verifies the output doesn't contain patterns that
 * violate constitution boundary descriptions or invariant rules.
 */
export function checkC2ConstitutionalAlignment(opts: CoherenceCheckOptions): CheckResult {
  const { output, constitution } = opts;

  if (!constitution) {
    return {
      check_id: "C2",
      name: "Constitutional Alignment",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No constitution provided — alignment check skipped",
    };
  }

  if (!output || !output.trim()) {
    return {
      check_id: "C2",
      name: "Constitutional Alignment",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No output to check against constitution",
    };
  }

  const outputLower = output.toLowerCase();
  const violations: string[] = [];

  // Check against boundary descriptions for prohibited patterns
  for (const boundary of constitution.boundaries) {
    if (boundary.severity === "critical" || boundary.severity === "high") {
      const boundaryKeywords = extractKeywords(boundary.description);
      // Look for negation patterns in boundaries (e.g., "must not", "never", "prohibited")
      const descLower = boundary.description.toLowerCase();
      const isProhibition = /\b(must not|never|prohibited|forbidden|cannot|shall not)\b/.test(descLower);

      if (isProhibition) {
        // Extract the subject of the prohibition
        const subjectWords = boundaryKeywords.filter(
          (w) => !["must", "never", "prohibited", "forbidden", "cannot", "shall"].includes(w),
        );
        const matchedSubject = subjectWords.filter((w) => outputLower.includes(w));
        if (matchedSubject.length >= 2 && subjectWords.length > 0) {
          violations.push(
            `Boundary ${boundary.id}: output may violate "${boundary.description}" (matched: ${matchedSubject.join(", ")})`,
          );
        }
      }
    }
  }

  if (violations.length > 0) {
    return {
      check_id: "C2",
      name: "Constitutional Alignment",
      passed: false,
      severity: "high",
      evidence: violations[0],
      details: `${violations.length} potential boundary violation(s) detected`,
    };
  }

  return {
    check_id: "C2",
    name: "Constitutional Alignment",
    passed: true,
    severity: "info",
    evidence: null,
    details: "No constitutional violations detected (structural check)",
  };
}

// ── C3: Instruction Adherence ────────────────────────────────────────

/**
 * C3: Instruction Adherence — does the output follow the query/instruction?
 *
 * Structural check: verifies output is non-empty and contains at least
 * some keywords from the query.
 */
export function checkC3InstructionAdherence(opts: CoherenceCheckOptions): CheckResult {
  const { query, output } = opts;

  if (!query || !query.trim()) {
    return {
      check_id: "C3",
      name: "Instruction Adherence",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No query provided — adherence check skipped",
    };
  }

  if (!output || !output.trim()) {
    return {
      check_id: "C3",
      name: "Instruction Adherence",
      passed: false,
      severity: "high",
      evidence: "Output is empty",
      details: "Empty output cannot adhere to instruction",
    };
  }

  const queryKeywords = extractKeywords(query);
  if (queryKeywords.length === 0) {
    return {
      check_id: "C3",
      name: "Instruction Adherence",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No significant keywords in query",
    };
  }

  const outputLower = output.toLowerCase();
  const matched = queryKeywords.filter((kw) => outputLower.includes(kw));
  const ratio = matched.length / queryKeywords.length;

  if (ratio === 0 && queryKeywords.length >= 2) {
    return {
      check_id: "C3",
      name: "Instruction Adherence",
      passed: false,
      severity: "medium",
      evidence: `None of the query keywords (${queryKeywords.slice(0, 5).join(", ")}) found in output`,
      details: "Output does not appear to address the query",
    };
  }

  return {
    check_id: "C3",
    name: "Instruction Adherence",
    passed: true,
    severity: "info",
    evidence: null,
    details: `${matched.length}/${queryKeywords.length} query keywords found in output`,
  };
}

// ── C4: Output Consistency ───────────────────────────────────────────

/**
 * C4: Output Consistency — is the output internally consistent?
 *
 * Structural check: always passes. Contradiction detection requires
 * semantic analysis beyond structural heuristics.
 */
export function checkC4OutputConsistency(opts: CoherenceCheckOptions): CheckResult {
  const { output } = opts;

  if (!output || !output.trim()) {
    return {
      check_id: "C4",
      name: "Output Consistency",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No output to check for consistency",
    };
  }

  return {
    check_id: "C4",
    name: "Output Consistency",
    passed: true,
    severity: "info",
    evidence: null,
    details: "Structural consistency check passed (semantic analysis not available)",
  };
}

// ── C5: Constraint Satisfaction ──────────────────────────────────────

/**
 * C5: Constraint Satisfaction — are all explicit constraints met?
 *
 * Structural check: verifies length constraints and format constraints
 * from the constitution's invariants.
 */
export function checkC5ConstraintSatisfaction(opts: CoherenceCheckOptions): CheckResult {
  const { output, constitution } = opts;

  if (!output || !output.trim()) {
    return {
      check_id: "C5",
      name: "Constraint Satisfaction",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No output to check constraints against",
    };
  }

  if (!constitution) {
    return {
      check_id: "C5",
      name: "Constraint Satisfaction",
      passed: true,
      severity: "info",
      evidence: null,
      details: "No constitution — constraint check skipped",
    };
  }

  const violations: string[] = [];

  // Check invariants for structural constraints
  for (const inv of constitution.invariants) {
    const ruleLower = inv.rule.toLowerCase();

    // Detect max length constraints in rules (e.g., "max 500 characters")
    const lengthMatch = ruleLower.match(/max(?:imum)?\s+(\d+)\s+(?:char|word|token)/);
    if (lengthMatch) {
      const limit = parseInt(lengthMatch[1], 10);
      const unit = ruleLower.includes("word") ? "words" : "characters";
      const actual = unit === "words" ? output.split(/\s+/).length : output.length;
      if (actual > limit) {
        violations.push(`${inv.id}: output exceeds ${limit} ${unit} (actual: ${actual})`);
      }
    }
  }

  if (violations.length > 0) {
    return {
      check_id: "C5",
      name: "Constraint Satisfaction",
      passed: false,
      severity: "medium",
      evidence: violations[0],
      details: `${violations.length} constraint violation(s) detected`,
    };
  }

  return {
    check_id: "C5",
    name: "Constraint Satisfaction",
    passed: true,
    severity: "info",
    evidence: null,
    details: "All structural constraints satisfied",
  };
}

// ── Run all checks ───────────────────────────────────────────────────

/**
 * Run all C1-C5 coherence checks and return the results.
 */
export function runCoherenceChecks(opts: CoherenceCheckOptions): CheckResult[] {
  return [
    checkC1ContextGrounding(opts),
    checkC2ConstitutionalAlignment(opts),
    checkC3InstructionAdherence(opts),
    checkC4OutputConsistency(opts),
    checkC5ConstraintSatisfaction(opts),
  ];
}
