#!/usr/bin/env node
/**
 * Minimal MCP echo server for testing downstream connections.
 *
 * Exposes two tools:
 *   - echo: returns the input text
 *   - fail: always returns an error
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "echo-server", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "echo",
      description: "Echo the input text",
      inputSchema: {
        type: "object" as const,
        properties: {
          text: { type: "string", description: "Text to echo" },
        },
        required: ["text"],
      },
    },
    {
      name: "fail",
      description: "Always returns an error",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "slow",
      description: "Responds after a delay",
      inputSchema: {
        type: "object" as const,
        properties: {
          delay_ms: { type: "number", description: "Delay in milliseconds" },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "echo") {
    const text = (args as Record<string, unknown>)?.text ?? "";
    return {
      content: [{ type: "text", text: String(text) }],
    };
  }

  if (name === "fail") {
    return {
      content: [{ type: "text", text: "Intentional failure" }],
      isError: true,
    };
  }

  if (name === "slow") {
    const delay = Number((args as Record<string, unknown>)?.delay_ms ?? 100);
    await new Promise((r) => setTimeout(r, delay));
    return {
      content: [{ type: "text", text: "done" }],
    };
  }

  return {
    content: [{ type: "text", text: `Unknown tool: ${name}` }],
    isError: true,
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Echo server error: ${err}\n`);
  process.exit(1);
});
