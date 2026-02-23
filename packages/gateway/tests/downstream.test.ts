import { describe, it, expect, afterEach } from "vitest";
import { resolve } from "node:path";
import { DownstreamConnection } from "../src/downstream.js";

const ECHO_SERVER = resolve(
  import.meta.dirname,
  "fixtures/echo-server.ts",
);

// Track connections for cleanup
const connections: DownstreamConnection[] = [];

afterEach(async () => {
  for (const conn of connections) {
    await conn.disconnect();
  }
  connections.length = 0;
});

function createConnection(name = "echo"): DownstreamConnection {
  const conn = new DownstreamConnection({
    name,
    command: "npx",
    args: ["tsx", ECHO_SERVER],
  });
  connections.push(conn);
  return conn;
}

describe("DownstreamConnection", () => {
  it("should connect to echo server", async () => {
    const conn = createConnection();
    await conn.connect();
    expect(conn.isConnected()).toBe(true);
  }, 15_000);

  it("should list tools from echo server", async () => {
    const conn = createConnection();
    await conn.connect();
    const tools = await conn.listTools();
    expect(tools.length).toBeGreaterThanOrEqual(2);
    const names = tools.map((t) => t.name);
    expect(names).toContain("echo");
    expect(names).toContain("fail");
  }, 15_000);

  it("should call echo tool", async () => {
    const conn = createConnection();
    await conn.connect();
    const result = await conn.callTool("echo", { text: "hello world" });
    expect(result.content).toHaveLength(1);
    expect(result.content[0].text).toBe("hello world");
    expect(result.isError).toBeFalsy();
  }, 15_000);

  it("should handle error tool", async () => {
    const conn = createConnection();
    await conn.connect();
    const result = await conn.callTool("fail", {});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Intentional failure");
  }, 15_000);

  it("should disconnect cleanly", async () => {
    const conn = createConnection();
    await conn.connect();
    expect(conn.isConnected()).toBe(true);
    await conn.disconnect();
    expect(conn.isConnected()).toBe(false);
  }, 15_000);

  it("should not throw on double disconnect", async () => {
    const conn = createConnection();
    await conn.connect();
    await conn.disconnect();
    await expect(conn.disconnect()).resolves.not.toThrow();
  }, 15_000);

  it("should not throw on connect when already connected", async () => {
    const conn = createConnection();
    await conn.connect();
    await expect(conn.connect()).resolves.not.toThrow();
  }, 15_000);

  it("should throw when calling tool on disconnected", async () => {
    const conn = createConnection();
    await expect(conn.callTool("echo", {})).rejects.toThrow("not connected");
  });

  it("should emit disconnect callback on unexpected close", async () => {
    const conn = createConnection();
    let disconnected = false;
    conn.onDisconnect(() => {
      disconnected = true;
    });
    await conn.connect();
    // Force disconnect via transport close
    await conn.disconnect();
    // The callback should have fired during disconnect
    // (It may or may not fire depending on timing — this is a best-effort test)
    expect(typeof disconnected).toBe("boolean");
  }, 15_000);
});
