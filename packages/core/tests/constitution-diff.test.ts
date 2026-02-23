import { describe, it, expect } from "vitest";
import {
  diffConstitutions,
  formatDiffText,
  formatDiffJson,
  isDriftingConstitution,
} from "../src/index.js";
import type { Constitution } from "../src/index.js";

function makeConstitution(overrides?: Partial<Constitution>): Constitution {
  return {
    schema_version: "1.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "A test agent",
      extensions: {},
    },
    provenance: {
      authored_by: "tester",
      approved_by: ["alice"],
      approval_date: "2025-01-01",
      approval_method: "manual",
      change_history: [],
      signature: null,
    },
    boundaries: [
      {
        id: "b1",
        description: "No external access",
        category: "scope",
        severity: "high",
      },
    ],
    trust_tiers: {
      autonomous: ["read_data"],
      requires_approval: ["write_data"],
      prohibited: ["delete_data"],
    },
    halt_conditions: [
      {
        id: "h1",
        trigger: "unauthorized_access",
        escalate_to: "admin",
        severity: "critical",
        enforcement: "halt",
      },
    ],
    invariants: [
      {
        id: "inv1",
        rule: "Always log actions",
        enforcement: "warn",
        check: null,
      },
    ],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
    ...overrides,
  };
}

describe("diffConstitutions", () => {
  it("should return empty diff for identical constitutions", () => {
    const a = makeConstitution();
    const b = makeConstitution();
    const diff = diffConstitutions(a, b);
    expect(diff.total_changes).toBe(0);
    for (const entries of Object.values(diff.sections)) {
      expect(entries).toHaveLength(0);
    }
  });

  it("should detect identity changes", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      identity: { ...a.identity, agent_name: "new-agent", domain: "production" },
    });
    const diff = diffConstitutions(a, b);
    expect(diff.sections.identity.length).toBeGreaterThanOrEqual(2);
    const nameDiff = diff.sections.identity.find(
      (e) => e.path === "identity.agent_name",
    );
    expect(nameDiff).toBeDefined();
    expect(nameDiff!.change_type).toBe("modified");
    expect(nameDiff!.old_value).toBe("test-agent");
    expect(nameDiff!.new_value).toBe("new-agent");
  });

  it("should detect provenance changes", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      provenance: {
        ...a.provenance,
        authored_by: "new-author",
        approved_by: ["alice", "bob"],
      },
    });
    const diff = diffConstitutions(a, b);
    expect(diff.sections.provenance.length).toBeGreaterThanOrEqual(2);
    const authorDiff = diff.sections.provenance.find(
      (e) => e.path === "provenance.authored_by",
    );
    expect(authorDiff).toBeDefined();
    expect(authorDiff!.old_value).toBe("tester");
    expect(authorDiff!.new_value).toBe("new-author");
  });

  it("should detect added boundaries", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      boundaries: [
        ...a.boundaries,
        { id: "b2", description: "New boundary", category: "safety", severity: "critical" },
      ],
    });
    const diff = diffConstitutions(a, b);
    const added = diff.sections.boundaries.find(
      (e) => e.path === "boundaries.b2" && e.change_type === "added",
    );
    expect(added).toBeDefined();
  });

  it("should detect removed boundaries", () => {
    const a = makeConstitution();
    const b = makeConstitution({ boundaries: [] });
    const diff = diffConstitutions(a, b);
    const removed = diff.sections.boundaries.find(
      (e) => e.path === "boundaries.b1" && e.change_type === "removed",
    );
    expect(removed).toBeDefined();
  });

  it("should detect modified boundaries", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      boundaries: [
        { id: "b1", description: "Updated description", category: "scope", severity: "critical" },
      ],
    });
    const diff = diffConstitutions(a, b);
    const modified = diff.sections.boundaries.find(
      (e) => e.path === "boundaries.b1" && e.change_type === "modified",
    );
    expect(modified).toBeDefined();
  });

  it("should detect added and removed invariants", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      invariants: [
        { id: "inv2", rule: "New invariant", enforcement: "halt" as const, check: "check_fn" },
      ],
    });
    const diff = diffConstitutions(a, b);
    const removed = diff.sections.invariants.find(
      (e) => e.path === "invariants.inv1" && e.change_type === "removed",
    );
    const added = diff.sections.invariants.find(
      (e) => e.path === "invariants.inv2" && e.change_type === "added",
    );
    expect(removed).toBeDefined();
    expect(added).toBeDefined();
  });

  it("should detect modified invariants", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      invariants: [
        { id: "inv1", rule: "Updated rule", enforcement: "halt" as const, check: null },
      ],
    });
    const diff = diffConstitutions(a, b);
    const modified = diff.sections.invariants.find(
      (e) => e.path === "invariants.inv1" && e.change_type === "modified",
    );
    expect(modified).toBeDefined();
  });

  it("should detect halt condition changes", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      halt_conditions: [
        {
          id: "h1",
          trigger: "unauthorized_access",
          escalate_to: "security-team",
          severity: "critical" as const,
          enforcement: "halt" as const,
        },
      ],
    });
    const diff = diffConstitutions(a, b);
    const modified = diff.sections.halt_conditions.find(
      (e) => e.path === "halt_conditions.h1" && e.change_type === "modified",
    );
    expect(modified).toBeDefined();
  });

  it("should detect trust tier changes", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      trust_tiers: {
        autonomous: ["read_data", "list_data"],
        requires_approval: ["write_data"],
        prohibited: ["delete_data"],
      },
    });
    const diff = diffConstitutions(a, b);
    const modified = diff.sections.trust_tiers.find(
      (e) => e.path === "trust_tiers.autonomous",
    );
    expect(modified).toBeDefined();
    expect(modified!.change_type).toBe("modified");
  });

  it("should detect added authority boundaries", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      authority_boundaries: {
        cannot_execute: ["deploy"],
        must_escalate: [],
        can_execute: ["test"],
        default_escalation: "ops",
      },
    });
    const diff = diffConstitutions(a, b);
    const added = diff.sections.authority_boundaries.find(
      (e) => e.change_type === "added",
    );
    expect(added).toBeDefined();
  });

  it("should detect removed authority boundaries", () => {
    const a = makeConstitution({
      authority_boundaries: {
        cannot_execute: ["deploy"],
        must_escalate: [],
        can_execute: ["test"],
        default_escalation: "ops",
      },
    });
    const b = makeConstitution({ authority_boundaries: null });
    const diff = diffConstitutions(a, b);
    const removed = diff.sections.authority_boundaries.find(
      (e) => e.change_type === "removed",
    );
    expect(removed).toBeDefined();
  });

  it("should detect metadata changes", () => {
    const a = makeConstitution();
    const b = makeConstitution({ schema_version: "2.0" });
    const diff = diffConstitutions(a, b);
    const modified = diff.sections.metadata.find(
      (e) => e.path === "schema_version",
    );
    expect(modified).toBeDefined();
    expect(modified!.old_value).toBe("1.0");
    expect(modified!.new_value).toBe("2.0");
    expect(diff.old_version).toBe("1.0");
    expect(diff.new_version).toBe("2.0");
  });

  it("should correctly count total changes", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      schema_version: "2.0",
      identity: { ...a.identity, agent_name: "changed" },
      boundaries: [],
    });
    const diff = diffConstitutions(a, b);
    let manual = 0;
    for (const entries of Object.values(diff.sections)) {
      manual += entries.length;
    }
    expect(diff.total_changes).toBe(manual);
    expect(diff.total_changes).toBeGreaterThanOrEqual(3);
  });
});

describe("formatDiffText", () => {
  it("should format empty diff", () => {
    const a = makeConstitution();
    const diff = diffConstitutions(a, a);
    const text = formatDiffText(diff);
    expect(text).toContain("Constitution Diff");
    expect(text).toContain("No changes detected");
  });

  it("should format diff with changes using +/-/~ symbols", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      identity: { ...a.identity, agent_name: "new-agent" },
      boundaries: [
        ...a.boundaries,
        { id: "b2", description: "Added", category: "safety" as const, severity: "high" as const },
      ],
    });
    const diff = diffConstitutions(a, b);
    const text = formatDiffText(diff);
    expect(text).toContain("~"); // modified
    expect(text).toContain("+"); // added
    expect(text).toContain("Total changes:");
    expect(text).toContain("[identity]");
    expect(text).toContain("[boundaries]");
  });

  it("should show version info", () => {
    const a = makeConstitution();
    const b = makeConstitution({ schema_version: "2.0" });
    const diff = diffConstitutions(a, b);
    const text = formatDiffText(diff);
    expect(text).toContain("1.0");
    expect(text).toContain("2.0");
  });
});

describe("formatDiffJson", () => {
  it("should return valid JSON", () => {
    const a = makeConstitution();
    const b = makeConstitution({ schema_version: "2.0" });
    const diff = diffConstitutions(a, b);
    const json = formatDiffJson(diff);
    const parsed = JSON.parse(json);
    expect(parsed.total_changes).toBeGreaterThan(0);
    expect(parsed.sections).toBeDefined();
  });
});

describe("isDriftingConstitution", () => {
  it("should return false when changes are below threshold", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      identity: { ...a.identity, agent_name: "changed" },
    });
    const diff = diffConstitutions(a, b);
    expect(isDriftingConstitution(diff)).toBe(false);
  });

  it("should return true when changes exceed threshold", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      schema_version: "2.0",
      identity: { ...a.identity, agent_name: "x", domain: "y", description: "z" },
      boundaries: [],
      invariants: [],
      halt_conditions: [],
    });
    const diff = diffConstitutions(a, b);
    expect(diff.total_changes).toBeGreaterThan(5);
    expect(isDriftingConstitution(diff)).toBe(true);
  });

  it("should respect custom threshold", () => {
    const a = makeConstitution();
    const b = makeConstitution({
      identity: { ...a.identity, agent_name: "changed" },
    });
    const diff = diffConstitutions(a, b);
    expect(isDriftingConstitution(diff, 0)).toBe(true);
  });
});
