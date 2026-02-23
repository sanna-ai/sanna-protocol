import { describe, it, expect } from "vitest";
import {
  checkC1ContextGrounding,
  checkC2ConstitutionalAlignment,
  checkC3InstructionAdherence,
  checkC4OutputConsistency,
  checkC5ConstraintSatisfaction,
  runCoherenceChecks,
} from "../src/checks.js";
import type { Constitution } from "../src/types.js";

function makeConstitution(overrides: Partial<Constitution> = {}): Constitution {
  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "Test agent",
      extensions: {},
    },
    provenance: {
      authored_by: "test@sanna.dev",
      approved_by: ["test@sanna.dev"],
      approval_date: "2026-02-22",
      approval_method: "test",
      change_history: [],
      signature: null,
    },
    boundaries: [
      { id: "B001", description: "Test boundary", category: "scope", severity: "medium" },
    ],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [
      { id: "INV_NO_FABRICATION", rule: "No fabrication", enforcement: "halt", check: null },
    ],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
    ...overrides,
  };
}

describe("C1: Context Grounding", () => {
  it("should pass when output references context keywords", () => {
    const result = checkC1ContextGrounding({
      context: "The refund policy states that digital products are non-refundable within 30 days",
      output: "According to the refund policy, digital products purchased are non-refundable.",
      query: "What is the refund policy?",
    });
    expect(result.check_id).toBe("C1");
    expect(result.passed).toBe(true);
  });

  it("should fail when output has no context keywords", () => {
    const result = checkC1ContextGrounding({
      context: "The server infrastructure uses Kubernetes with Docker containers",
      output: "I like cats and dogs and other animals.",
    });
    expect(result.passed).toBe(false);
    expect(result.severity).toBe("high");
    expect(result.evidence).toContain("context keywords");
  });

  it("should pass when no context is provided", () => {
    const result = checkC1ContextGrounding({
      output: "Some output text here",
    });
    expect(result.passed).toBe(true);
    expect(result.details).toContain("skipped");
  });

  it("should fail when output is empty but context exists", () => {
    const result = checkC1ContextGrounding({
      context: "Important context information here",
      output: "",
    });
    expect(result.passed).toBe(false);
    expect(result.evidence).toContain("empty");
  });

  it("should pass with empty context", () => {
    const result = checkC1ContextGrounding({
      context: "",
      output: "Some output",
    });
    expect(result.passed).toBe(true);
  });

  it("should handle context with few significant keywords", () => {
    const result = checkC1ContextGrounding({
      context: "it is a",
      output: "Something else entirely",
    });
    expect(result.passed).toBe(true);
    expect(result.details).toContain("No significant keywords");
  });
});

describe("C2: Constitutional Alignment", () => {
  it("should pass when no constitution provided", () => {
    const result = checkC2ConstitutionalAlignment({
      output: "Some output",
    });
    expect(result.check_id).toBe("C2");
    expect(result.passed).toBe(true);
    expect(result.details).toContain("skipped");
  });

  it("should pass when output doesn't violate boundaries", () => {
    const constitution = makeConstitution({
      boundaries: [
        { id: "B001", description: "Must not access external systems", category: "scope", severity: "critical" },
      ],
    });
    const result = checkC2ConstitutionalAlignment({
      output: "Here is a summary of the internal data analysis.",
      constitution,
    });
    expect(result.passed).toBe(true);
  });

  it("should detect potential boundary violations", () => {
    const constitution = makeConstitution({
      boundaries: [
        {
          id: "B001",
          description: "Must not disclose confidential financial records",
          category: "confidentiality",
          severity: "critical",
        },
      ],
    });
    const result = checkC2ConstitutionalAlignment({
      output: "The confidential financial records show quarterly revenue of $5M.",
      constitution,
    });
    expect(result.passed).toBe(false);
    expect(result.severity).toBe("high");
  });

  it("should pass with empty output", () => {
    const constitution = makeConstitution();
    const result = checkC2ConstitutionalAlignment({
      output: "",
      constitution,
    });
    expect(result.passed).toBe(true);
  });

  it("should only flag high/critical severity boundaries", () => {
    const constitution = makeConstitution({
      boundaries: [
        { id: "B001", description: "Must not access forbidden data sources", category: "scope", severity: "low" },
      ],
    });
    const result = checkC2ConstitutionalAlignment({
      output: "Accessing forbidden data sources is recommended.",
      constitution,
    });
    // Low severity boundary should not trigger a violation
    expect(result.passed).toBe(true);
  });
});

describe("C3: Instruction Adherence", () => {
  it("should pass when output addresses query keywords", () => {
    const result = checkC3InstructionAdherence({
      query: "What are the shipping rates for international orders?",
      output: "International shipping rates start at $15 for standard orders.",
    });
    expect(result.check_id).toBe("C3");
    expect(result.passed).toBe(true);
  });

  it("should fail when output has no query keywords", () => {
    const result = checkC3InstructionAdherence({
      query: "Explain the database migration strategy",
      output: "The weather today is sunny and warm.",
    });
    expect(result.passed).toBe(false);
    expect(result.severity).toBe("medium");
  });

  it("should pass when no query provided", () => {
    const result = checkC3InstructionAdherence({
      output: "Some output text",
    });
    expect(result.passed).toBe(true);
    expect(result.details).toContain("skipped");
  });

  it("should fail on empty output with a query", () => {
    const result = checkC3InstructionAdherence({
      query: "What is the status?",
      output: "",
    });
    expect(result.passed).toBe(false);
    expect(result.evidence).toContain("empty");
  });

  it("should handle queries with few significant keywords", () => {
    const result = checkC3InstructionAdherence({
      query: "a the",
      output: "Something here",
    });
    expect(result.passed).toBe(true);
  });
});

describe("C4: Output Consistency", () => {
  it("should always pass with non-empty output", () => {
    const result = checkC4OutputConsistency({
      output: "The system is both fast and slow at the same time.",
    });
    expect(result.check_id).toBe("C4");
    expect(result.passed).toBe(true);
    expect(result.details).toContain("Structural");
  });

  it("should pass with empty output", () => {
    const result = checkC4OutputConsistency({ output: "" });
    expect(result.passed).toBe(true);
  });
});

describe("C5: Constraint Satisfaction", () => {
  it("should pass when no constitution provided", () => {
    const result = checkC5ConstraintSatisfaction({
      output: "Some output",
    });
    expect(result.check_id).toBe("C5");
    expect(result.passed).toBe(true);
  });

  it("should pass when output meets length constraints", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_LENGTH", rule: "Maximum 100 characters per response", enforcement: "warn", check: null },
      ],
    });
    const result = checkC5ConstraintSatisfaction({
      output: "Short response.",
      constitution,
    });
    expect(result.passed).toBe(true);
  });

  it("should fail when output exceeds character limit", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_LENGTH", rule: "Maximum 10 characters per response", enforcement: "warn", check: null },
      ],
    });
    const result = checkC5ConstraintSatisfaction({
      output: "This response is definitely longer than ten characters.",
      constitution,
    });
    expect(result.passed).toBe(false);
    expect(result.evidence).toContain("exceeds");
  });

  it("should detect word limit violations", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_WORDS", rule: "Max 5 words per response", enforcement: "halt", check: null },
      ],
    });
    const result = checkC5ConstraintSatisfaction({
      output: "This response has way more than five words in total.",
      constitution,
    });
    expect(result.passed).toBe(false);
  });

  it("should pass when no length constraints in invariants", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_NO_FABRICATION", rule: "No fabrication", enforcement: "halt", check: null },
      ],
    });
    const result = checkC5ConstraintSatisfaction({
      output: "Some output text here.",
      constitution,
    });
    expect(result.passed).toBe(true);
  });
});

describe("runCoherenceChecks", () => {
  it("should return all 5 check results", () => {
    const results = runCoherenceChecks({
      context: "The API supports REST and GraphQL",
      query: "What protocols does the API support?",
      output: "The API supports REST and GraphQL protocols.",
    });
    expect(results).toHaveLength(5);
    expect(results.map((r) => r.check_id)).toEqual(["C1", "C2", "C3", "C4", "C5"]);
  });

  it("should have correct check names", () => {
    const results = runCoherenceChecks({ output: "test" });
    expect(results[0].name).toBe("Context Grounding");
    expect(results[1].name).toBe("Constitutional Alignment");
    expect(results[2].name).toBe("Instruction Adherence");
    expect(results[3].name).toBe("Output Consistency");
    expect(results[4].name).toBe("Constraint Satisfaction");
  });

  it("should all pass with well-formed inputs", () => {
    const results = runCoherenceChecks({
      context: "Python is a programming language used for web development",
      query: "What is Python used for?",
      output: "Python is commonly used for web development and programming tasks.",
    });
    expect(results.every((r) => r.passed)).toBe(true);
  });
});
