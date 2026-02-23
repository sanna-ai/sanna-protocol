import { describe, it, expect } from "vitest";
import {
  namespaceTool,
  parseNamespacedTool,
  namespaceToolList,
  denamespaceArgs,
} from "../src/tool-namespace.js";

describe("namespaceTool", () => {
  it("should prefix tool with downstream name", () => {
    expect(namespaceTool("notion", "search")).toBe("notion_search");
  });

  it("should handle tools with underscores", () => {
    expect(namespaceTool("fs", "read_file")).toBe("fs_read_file");
  });
});

describe("parseNamespacedTool", () => {
  it("should split on first underscore", () => {
    const result = parseNamespacedTool("notion_search");
    expect(result).toEqual({ downstream: "notion", tool: "search" });
  });

  it("should handle tools with underscores", () => {
    const result = parseNamespacedTool("fs_read_file");
    expect(result).toEqual({ downstream: "fs", tool: "read_file" });
  });

  it("should return null for names without underscore", () => {
    expect(parseNamespacedTool("notool")).toBeNull();
  });

  it("should round-trip with namespaceTool", () => {
    const ns = namespaceTool("server", "my_tool");
    const parsed = parseNamespacedTool(ns);
    expect(parsed).toEqual({ downstream: "server", tool: "my_tool" });
  });
});

describe("namespaceToolList", () => {
  it("should prefix all tool names", () => {
    const tools = [
      { name: "search", description: "Search docs" },
      { name: "create_page", description: "Create a page" },
    ];
    const result = namespaceToolList("notion", tools);
    expect(result).toHaveLength(2);
    expect(result[0].name).toBe("notion_search");
    expect(result[1].name).toBe("notion_create_page");
    // Description preserved
    expect(result[0].description).toBe("Search docs");
  });

  it("should preserve other tool properties", () => {
    const tools = [
      {
        name: "tool",
        description: "desc",
        inputSchema: { type: "object", properties: {} },
      },
    ];
    const result = namespaceToolList("s", tools);
    expect(result[0].inputSchema).toBeDefined();
  });

  it("should handle empty list", () => {
    expect(namespaceToolList("s", [])).toEqual([]);
  });
});

describe("denamespaceArgs", () => {
  it("should pass through args unchanged", () => {
    const args = { text: "hello", count: 5 };
    expect(denamespaceArgs("notion_search", args)).toEqual(args);
  });
});

describe("multi-downstream aggregation", () => {
  it("should produce unique names for same-named tools from different downstreams", () => {
    const toolsA = namespaceToolList("server-a", [
      { name: "search" },
    ]);
    const toolsB = namespaceToolList("server-b", [
      { name: "search" },
    ]);
    const all = [...toolsA, ...toolsB];
    const names = all.map((t) => t.name);
    expect(names).toEqual(["server-a_search", "server-b_search"]);
    // All unique
    expect(new Set(names).size).toBe(names.length);
  });
});
