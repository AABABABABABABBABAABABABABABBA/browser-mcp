#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { zodToJsonSchema } from "zod-to-json-schema";
import { browserTools } from "./tools/browser.js";
import { networkTools } from "./tools/network.js";
import { scanTools } from "./tools/scan.js";
import { utilTools } from "./tools/util.js";
import { hub } from "./browser.js";
import type { ToolDef } from "./types.js";

const ALL: ToolDef[] = [...browserTools, ...networkTools, ...scanTools, ...utilTools];
const byName = new Map(ALL.map((t) => [t.name, t]));

const server = new Server(
  { name: "browser-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: ALL.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: zodToJsonSchema(t.schema, { target: "jsonSchema7" }) as any,
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const tool = byName.get(req.params.name);
  if (!tool) return { content: [{ type: "text", text: `unknown tool: ${req.params.name}` }], isError: true };
  try {
    const parsed = tool.schema.parse(req.params.arguments ?? {});
    const result = await tool.handler(parsed);
    return result as any;
  } catch (e: any) {
    return { content: [{ type: "text", text: `error: ${e?.message ?? String(e)}` }], isError: true };
  }
});

const shutdown = async () => { try { await hub.shutdown(); } catch { /* pumppet */ } process.exit(0); };
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`browser-mcp ready — ${ALL.length} tools registered`);
