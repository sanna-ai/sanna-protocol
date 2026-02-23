/**
 * Sanna Protocol — Constitution Diff
 *
 * Structural comparison of two parsed constitutions.
 * Detects added, removed, and modified fields across all sections.
 */

import type {
  Constitution,
  DiffEntry,
  DiffResult,
  DiffSection,
} from "./types.js";

// ── Internal helpers ────────────────────────────────────────────────

function emptyResult(
  oldVersion?: string,
  newVersion?: string,
): DiffResult {
  return {
    sections: {
      identity: [],
      provenance: [],
      boundaries: [],
      trust_tiers: [],
      halt_conditions: [],
      invariants: [],
      authority_boundaries: [],
      trusted_sources: [],
      metadata: [],
    },
    total_changes: 0,
    old_version: oldVersion,
    new_version: newVersion,
  };
}

function addEntry(
  result: DiffResult,
  section: DiffSection,
  entry: DiffEntry,
): void {
  result.sections[section].push(entry);
  result.total_changes++;
}

function stringify(val: unknown): string {
  if (val === null || val === undefined) return "";
  if (typeof val === "string") return val;
  return JSON.stringify(val);
}

// ── Section diffing ─────────────────────────────────────────────────

function diffIdentity(a: Constitution, b: Constitution, result: DiffResult): void {
  const fields: (keyof Constitution["identity"])[] = [
    "agent_name",
    "domain",
    "description",
  ];
  for (const field of fields) {
    const oldVal = a.identity[field];
    const newVal = b.identity[field];
    if (stringify(oldVal) !== stringify(newVal)) {
      addEntry(result, "identity", {
        path: `identity.${field}`,
        change_type: "modified",
        old_value: oldVal,
        new_value: newVal,
      });
    }
  }
}

function diffProvenance(a: Constitution, b: Constitution, result: DiffResult): void {
  const fields: (keyof Constitution["provenance"])[] = [
    "authored_by",
    "approval_date",
    "approval_method",
  ];
  for (const field of fields) {
    const oldVal = a.provenance[field];
    const newVal = b.provenance[field];
    if (stringify(oldVal) !== stringify(newVal)) {
      addEntry(result, "provenance", {
        path: `provenance.${field}`,
        change_type: "modified",
        old_value: oldVal,
        new_value: newVal,
      });
    }
  }

  // approved_by
  const oldApprovers = JSON.stringify(a.provenance.approved_by);
  const newApprovers = JSON.stringify(b.provenance.approved_by);
  if (oldApprovers !== newApprovers) {
    addEntry(result, "provenance", {
      path: "provenance.approved_by",
      change_type: "modified",
      old_value: a.provenance.approved_by,
      new_value: b.provenance.approved_by,
    });
  }
}

function diffBoundaries(a: Constitution, b: Constitution, result: DiffResult): void {
  const oldMap = new Map(a.boundaries.map((b) => [b.id, b]));
  const newMap = new Map(b.boundaries.map((b) => [b.id, b]));

  // Removed boundaries
  for (const [id, boundary] of oldMap) {
    if (!newMap.has(id)) {
      addEntry(result, "boundaries", {
        path: `boundaries.${id}`,
        change_type: "removed",
        old_value: boundary,
      });
    }
  }

  // Added boundaries
  for (const [id, boundary] of newMap) {
    if (!oldMap.has(id)) {
      addEntry(result, "boundaries", {
        path: `boundaries.${id}`,
        change_type: "added",
        new_value: boundary,
      });
    }
  }

  // Modified boundaries
  for (const [id, oldBoundary] of oldMap) {
    const newBoundary = newMap.get(id);
    if (!newBoundary) continue;

    if (
      oldBoundary.description !== newBoundary.description ||
      oldBoundary.category !== newBoundary.category ||
      oldBoundary.severity !== newBoundary.severity
    ) {
      addEntry(result, "boundaries", {
        path: `boundaries.${id}`,
        change_type: "modified",
        old_value: oldBoundary,
        new_value: newBoundary,
      });
    }
  }
}

function diffInvariants(a: Constitution, b: Constitution, result: DiffResult): void {
  const oldMap = new Map(a.invariants.map((inv) => [inv.id, inv]));
  const newMap = new Map(b.invariants.map((inv) => [inv.id, inv]));

  for (const [id, inv] of oldMap) {
    if (!newMap.has(id)) {
      addEntry(result, "invariants", {
        path: `invariants.${id}`,
        change_type: "removed",
        old_value: inv,
      });
    }
  }

  for (const [id, inv] of newMap) {
    if (!oldMap.has(id)) {
      addEntry(result, "invariants", {
        path: `invariants.${id}`,
        change_type: "added",
        new_value: inv,
      });
    }
  }

  for (const [id, oldInv] of oldMap) {
    const newInv = newMap.get(id);
    if (!newInv) continue;

    if (
      oldInv.rule !== newInv.rule ||
      oldInv.enforcement !== newInv.enforcement ||
      oldInv.check !== newInv.check
    ) {
      addEntry(result, "invariants", {
        path: `invariants.${id}`,
        change_type: "modified",
        old_value: oldInv,
        new_value: newInv,
      });
    }
  }
}

function diffHaltConditions(a: Constitution, b: Constitution, result: DiffResult): void {
  const oldMap = new Map(a.halt_conditions.map((h) => [h.id, h]));
  const newMap = new Map(b.halt_conditions.map((h) => [h.id, h]));

  for (const [id, h] of oldMap) {
    if (!newMap.has(id)) {
      addEntry(result, "halt_conditions", {
        path: `halt_conditions.${id}`,
        change_type: "removed",
        old_value: h,
      });
    }
  }

  for (const [id, h] of newMap) {
    if (!oldMap.has(id)) {
      addEntry(result, "halt_conditions", {
        path: `halt_conditions.${id}`,
        change_type: "added",
        new_value: h,
      });
    }
  }

  for (const [id, oldH] of oldMap) {
    const newH = newMap.get(id);
    if (!newH) continue;

    if (
      oldH.trigger !== newH.trigger ||
      oldH.escalate_to !== newH.escalate_to ||
      oldH.severity !== newH.severity ||
      oldH.enforcement !== newH.enforcement
    ) {
      addEntry(result, "halt_conditions", {
        path: `halt_conditions.${id}`,
        change_type: "modified",
        old_value: oldH,
        new_value: newH,
      });
    }
  }
}

function diffTrustTiers(a: Constitution, b: Constitution, result: DiffResult): void {
  const tiers: (keyof Constitution["trust_tiers"])[] = [
    "autonomous",
    "requires_approval",
    "prohibited",
  ];
  for (const tier of tiers) {
    const oldVal = JSON.stringify(a.trust_tiers[tier]);
    const newVal = JSON.stringify(b.trust_tiers[tier]);
    if (oldVal !== newVal) {
      addEntry(result, "trust_tiers", {
        path: `trust_tiers.${tier}`,
        change_type: "modified",
        old_value: a.trust_tiers[tier],
        new_value: b.trust_tiers[tier],
      });
    }
  }
}

function diffAuthorityBoundaries(
  a: Constitution,
  b: Constitution,
  result: DiffResult,
): void {
  const oldAb = a.authority_boundaries;
  const newAb = b.authority_boundaries;

  if (!oldAb && !newAb) return;

  if (!oldAb && newAb) {
    addEntry(result, "authority_boundaries", {
      path: "authority_boundaries",
      change_type: "added",
      new_value: newAb,
    });
    return;
  }

  if (oldAb && !newAb) {
    addEntry(result, "authority_boundaries", {
      path: "authority_boundaries",
      change_type: "removed",
      old_value: oldAb,
    });
    return;
  }

  // Both exist — compare lists
  const oldCe = JSON.stringify(oldAb!.cannot_execute);
  const newCe = JSON.stringify(newAb!.cannot_execute);
  if (oldCe !== newCe) {
    addEntry(result, "authority_boundaries", {
      path: "authority_boundaries.cannot_execute",
      change_type: "modified",
      old_value: oldAb!.cannot_execute,
      new_value: newAb!.cannot_execute,
    });
  }

  const oldExec = JSON.stringify(oldAb!.can_execute);
  const newExec = JSON.stringify(newAb!.can_execute);
  if (oldExec !== newExec) {
    addEntry(result, "authority_boundaries", {
      path: "authority_boundaries.can_execute",
      change_type: "modified",
      old_value: oldAb!.can_execute,
      new_value: newAb!.can_execute,
    });
  }

  const oldMust = JSON.stringify(oldAb!.must_escalate);
  const newMust = JSON.stringify(newAb!.must_escalate);
  if (oldMust !== newMust) {
    addEntry(result, "authority_boundaries", {
      path: "authority_boundaries.must_escalate",
      change_type: "modified",
      old_value: oldAb!.must_escalate,
      new_value: newAb!.must_escalate,
    });
  }

  if (oldAb!.default_escalation !== newAb!.default_escalation) {
    addEntry(result, "authority_boundaries", {
      path: "authority_boundaries.default_escalation",
      change_type: "modified",
      old_value: oldAb!.default_escalation,
      new_value: newAb!.default_escalation,
    });
  }
}

function diffTrustedSources(
  a: Constitution,
  b: Constitution,
  result: DiffResult,
): void {
  const oldTs = a.trusted_sources;
  const newTs = b.trusted_sources;

  if (!oldTs && !newTs) return;

  if (!oldTs && newTs) {
    addEntry(result, "trusted_sources", {
      path: "trusted_sources",
      change_type: "added",
      new_value: newTs,
    });
    return;
  }

  if (oldTs && !newTs) {
    addEntry(result, "trusted_sources", {
      path: "trusted_sources",
      change_type: "removed",
      old_value: oldTs,
    });
    return;
  }

  const tiers: (keyof NonNullable<Constitution["trusted_sources"]>)[] = [
    "tier_1", "tier_2", "tier_3", "untrusted",
  ];
  for (const tier of tiers) {
    const oldVal = JSON.stringify(oldTs![tier]);
    const newVal = JSON.stringify(newTs![tier]);
    if (oldVal !== newVal) {
      addEntry(result, "trusted_sources", {
        path: `trusted_sources.${tier}`,
        change_type: "modified",
        old_value: oldTs![tier],
        new_value: newTs![tier],
      });
    }
  }
}

function diffMetadata(a: Constitution, b: Constitution, result: DiffResult): void {
  if (a.schema_version !== b.schema_version) {
    addEntry(result, "metadata", {
      path: "schema_version",
      change_type: "modified",
      old_value: a.schema_version,
      new_value: b.schema_version,
    });
  }

  if ((a.policy_hash ?? "") !== (b.policy_hash ?? "")) {
    addEntry(result, "metadata", {
      path: "policy_hash",
      change_type: "modified",
      old_value: a.policy_hash,
      new_value: b.policy_hash,
    });
  }
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Compute a structural diff between two parsed constitutions.
 */
export function diffConstitutions(
  a: Constitution,
  b: Constitution,
): DiffResult {
  const result = emptyResult(a.schema_version, b.schema_version);

  diffIdentity(a, b, result);
  diffProvenance(a, b, result);
  diffBoundaries(a, b, result);
  diffInvariants(a, b, result);
  diffHaltConditions(a, b, result);
  diffTrustTiers(a, b, result);
  diffAuthorityBoundaries(a, b, result);
  diffTrustedSources(a, b, result);
  diffMetadata(a, b, result);

  return result;
}

// ── Formatting ──────────────────────────────────────────────────────

/**
 * Format a diff result as human-readable text.
 */
export function formatDiffText(diff: DiffResult): string {
  const lines: string[] = [];

  lines.push("Constitution Diff");
  lines.push("=".repeat(50));

  if (diff.old_version || diff.new_version) {
    lines.push(
      `Versions: ${diff.old_version ?? "?"} → ${diff.new_version ?? "?"}`,
    );
  }

  if (diff.total_changes === 0) {
    lines.push("  No changes detected.");
    return lines.join("\n");
  }

  lines.push(`Total changes: ${diff.total_changes}`);
  lines.push("");

  for (const [section, entries] of Object.entries(diff.sections)) {
    if (entries.length === 0) continue;

    lines.push(`[${section}]`);
    for (const entry of entries as DiffEntry[]) {
      const symbol =
        entry.change_type === "added"
          ? "+"
          : entry.change_type === "removed"
            ? "-"
            : "~";
      let line = `  ${symbol} ${entry.path}`;

      if (entry.change_type === "modified") {
        const oldStr = stringify(entry.old_value);
        const newStr = stringify(entry.new_value);
        if (oldStr.length < 60 && newStr.length < 60) {
          line += `: ${oldStr} → ${newStr}`;
        }
      } else if (entry.change_type === "added" && entry.new_value !== undefined) {
        const newStr = stringify(entry.new_value);
        if (newStr.length < 60) {
          line += `: ${newStr}`;
        }
      } else if (entry.change_type === "removed" && entry.old_value !== undefined) {
        const oldStr = stringify(entry.old_value);
        if (oldStr.length < 60) {
          line += `: ${oldStr}`;
        }
      }

      lines.push(line);
    }
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Format a diff result as machine-readable JSON.
 */
export function formatDiffJson(diff: DiffResult): string {
  return JSON.stringify(diff, null, 2);
}

/**
 * Heuristic to detect if a constitution has drifted significantly.
 *
 * @param diff The diff result to evaluate
 * @param threshold Maximum number of changes before considering it drift (default: 5)
 * @returns true if the number of changes exceeds the threshold
 */
export function isDriftingConstitution(
  diff: DiffResult,
  threshold: number = 5,
): boolean {
  return diff.total_changes > threshold;
}
