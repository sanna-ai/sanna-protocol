import { describe, it, expect } from "vitest";
import {
  injectJustificationParam,
  extractJustification,
} from "../src/schema-mutation.js";

describe("injectJustificationParam", () => {
  it("should add _justification to empty schema", () => {
    const result = injectJustificationParam({ type: "object" });
    expect(result.properties).toBeDefined();
    expect(result.properties!._justification).toBeDefined();
    expect((result.properties!._justification as any).type).toBe("string");
  });

  it("should preserve existing properties", () => {
    const result = injectJustificationParam({
      type: "object",
      properties: {
        text: { type: "string" },
        count: { type: "number" },
      },
    });
    expect(result.properties!.text).toBeDefined();
    expect(result.properties!.count).toBeDefined();
    expect(result.properties!._justification).toBeDefined();
  });

  it("should not modify the original schema", () => {
    const original = {
      type: "object",
      properties: { text: { type: "string" } },
    };
    const result = injectJustificationParam(original);
    expect(original.properties._justification).toBeUndefined();
    expect(result.properties!._justification).toBeDefined();
  });

  it("should not add _justification to required", () => {
    const result = injectJustificationParam({
      type: "object",
      required: ["text"],
      properties: { text: { type: "string" } },
    });
    expect(result.required).toEqual(["text"]);
  });

  it("should include a description", () => {
    const result = injectJustificationParam({});
    const desc = (result.properties!._justification as any).description;
    expect(desc).toContain("justification");
  });
});

describe("extractJustification", () => {
  it("should extract _justification and return clean args", () => {
    const { justification, cleanArgs } = extractJustification({
      text: "hello",
      _justification: "I need to do this because...",
    });
    expect(justification).toBe("I need to do this because...");
    expect(cleanArgs).toEqual({ text: "hello" });
    expect(cleanArgs).not.toHaveProperty("_justification");
  });

  it("should return undefined justification when not present", () => {
    const { justification, cleanArgs } = extractJustification({
      text: "hello",
    });
    expect(justification).toBeUndefined();
    expect(cleanArgs).toEqual({ text: "hello" });
  });

  it("should return undefined for non-string _justification", () => {
    const { justification } = extractJustification({
      _justification: 42,
    });
    expect(justification).toBeUndefined();
  });
});
