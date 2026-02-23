import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
import { migrateClaudeConfig, migrateCursorConfig } from "../src/migrate.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-migrate-test-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("migrateClaudeConfig", () => {
  it("should convert Claude Desktop config to gateway YAML", () => {
    const sourcePath = join(tmpDir, "claude_config.json");
    writeFileSync(
      sourcePath,
      JSON.stringify({
        mcpServers: {
          "notion-server": {
            command: "npx",
            args: ["-y", "@notionhq/notion-mcp-server"],
            env: { NOTION_API_KEY: "secret" },
          },
          "filesystem": {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
          },
        },
      }),
    );

    const outputPath = join(tmpDir, "gateway.yaml");
    const result = migrateClaudeConfig(sourcePath, outputPath);
    expect(result).toBe(outputPath);
    expect(existsSync(outputPath)).toBe(true);

    const content = yaml.load(readFileSync(outputPath, "utf-8")) as any;
    expect(content.downstreams).toHaveLength(2);
    expect(content.downstreams[0].name).toBe("notion-server");
    expect(content.downstreams[0].command).toBe("npx");
    expect(content.downstreams[1].name).toBe("filesystem");
  });

  it("should create placeholder constitution", () => {
    const sourcePath = join(tmpDir, "claude_config.json");
    writeFileSync(
      sourcePath,
      JSON.stringify({
        mcpServers: {
          test: { command: "node", args: ["server.js"] },
        },
      }),
    );

    const outputPath = join(tmpDir, "gateway.yaml");
    migrateClaudeConfig(sourcePath, outputPath);

    const constPath = join(tmpDir, "constitution.yaml");
    expect(existsSync(constPath)).toBe(true);
    const content = yaml.load(readFileSync(constPath, "utf-8")) as any;
    expect(content.schema_version).toBe("1.0");
    expect(content.identity).toBeDefined();
  });

  it("should throw for missing source file", () => {
    expect(() =>
      migrateClaudeConfig(join(tmpDir, "nonexistent.json")),
    ).toThrow("not found");
  });

  it("should handle empty mcpServers", () => {
    const sourcePath = join(tmpDir, "config.json");
    writeFileSync(sourcePath, JSON.stringify({ mcpServers: {} }));
    const outputPath = join(tmpDir, "gateway.yaml");
    migrateClaudeConfig(sourcePath, outputPath);

    const content = yaml.load(readFileSync(outputPath, "utf-8")) as any;
    expect(content.downstreams).toHaveLength(0);
  });

  it("should set advisory mode by default", () => {
    const sourcePath = join(tmpDir, "config.json");
    writeFileSync(
      sourcePath,
      JSON.stringify({
        mcpServers: { test: { command: "node" } },
      }),
    );
    const outputPath = join(tmpDir, "gateway.yaml");
    migrateClaudeConfig(sourcePath, outputPath);

    const content = yaml.load(readFileSync(outputPath, "utf-8")) as any;
    expect(content.gateway.enforcement.mode).toBe("advisory");
  });
});

describe("migrateCursorConfig", () => {
  it("should convert Cursor config to gateway YAML", () => {
    const sourcePath = join(tmpDir, "cursor_config.json");
    writeFileSync(
      sourcePath,
      JSON.stringify({
        mcpServers: {
          "my-server": {
            command: "python",
            args: ["server.py"],
          },
        },
      }),
    );

    const outputPath = join(tmpDir, "gateway.yaml");
    const result = migrateCursorConfig(sourcePath, outputPath);
    expect(result).toBe(outputPath);

    const content = yaml.load(readFileSync(outputPath, "utf-8")) as any;
    expect(content.downstreams).toHaveLength(1);
    expect(content.downstreams[0].name).toBe("my-server");
    expect(content.downstreams[0].command).toBe("python");
  });

  it("should throw for missing source file", () => {
    expect(() =>
      migrateCursorConfig(join(tmpDir, "nonexistent.json")),
    ).toThrow("not found");
  });
});
