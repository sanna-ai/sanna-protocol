/**
 * Sanna Gateway — Schema Mutation
 *
 * Injects _justification parameter into tool input schemas
 * so agents can provide justification for escalation overrides.
 */

// ── Types ────────────────────────────────────────────────────────────

export interface ToolSchema {
  type?: string;
  properties?: Record<string, unknown>;
  required?: string[];
  [key: string]: unknown;
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Inject an optional _justification string parameter into a tool's input schema.
 *
 * Returns a new schema object (does not mutate the original).
 */
export function injectJustificationParam(toolSchema: ToolSchema): ToolSchema {
  const schema = { ...toolSchema };
  schema.properties = {
    ...(schema.properties ?? {}),
    _justification: {
      type: "string",
      description:
        "Optional justification for this tool call. " +
        "Used when the tool requires escalation approval.",
    },
  };
  return schema;
}

/**
 * Extract _justification from tool call arguments.
 *
 * Returns the justification (if present) and the cleaned args
 * with _justification removed.
 */
export function extractJustification(
  args: Record<string, unknown>,
): { justification: string | undefined; cleanArgs: Record<string, unknown> } {
  const { _justification, ...cleanArgs } = args;
  return {
    justification: typeof _justification === "string" ? _justification : undefined,
    cleanArgs,
  };
}
