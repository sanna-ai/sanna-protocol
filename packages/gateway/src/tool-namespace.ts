/**
 * Sanna Gateway — Tool Namespacing
 *
 * Multi-downstream tool name management.
 * Downstream tools are prefixed: {downstreamName}_{toolName}
 */

// ── Namespace separator ──────────────────────────────────────────────

const SEPARATOR = "_";

// ── Public API ───────────────────────────────────────────────────────

/**
 * Create a namespaced tool name: "{downstreamName}_{toolName}"
 */
export function namespaceTool(downstreamName: string, toolName: string): string {
  return `${downstreamName}${SEPARATOR}${toolName}`;
}

/**
 * Parse a namespaced tool name back into downstream and tool.
 *
 * Splits on the first underscore only, so tool names may contain underscores.
 */
export function parseNamespacedTool(
  namespacedName: string,
): { downstream: string; tool: string } | null {
  const idx = namespacedName.indexOf(SEPARATOR);
  if (idx < 0) return null;
  return {
    downstream: namespacedName.slice(0, idx),
    tool: namespacedName.slice(idx + 1),
  };
}

/**
 * Tool definition as returned by MCP tools/list.
 */
export interface ToolDef {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Namespace all tools in a list, prefixing each name.
 */
export function namespaceToolList(
  downstreamName: string,
  tools: ToolDef[],
): ToolDef[] {
  return tools.map((tool) => ({
    ...tool,
    name: namespaceTool(downstreamName, tool.name),
  }));
}

/**
 * Strip namespace from args (pass-through — args don't change).
 */
export function denamespaceArgs(
  _namespacedName: string,
  args: Record<string, unknown>,
): Record<string, unknown> {
  // Args are forwarded as-is; namespace only affects tool routing
  return args;
}
