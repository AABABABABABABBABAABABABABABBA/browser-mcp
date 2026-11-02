#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { zodToJsonSchema } from "zod-to-json-schema";
import { browserTools } from "./tools/browser.js";
import { networkTools } from "./tools/network.js";
import { scanTools } from "./tools/scan.js";
import { utilTools } from "./tools/util.js";
import { consoleTools } from "./tools/console.js";
import { sourceTools } from "./tools/source.js";
import { userscriptTools } from "./tools/userscript.js";
import { apiTools } from "./tools/api.js";
import { vulnTools } from "./tools/vuln.js";
import { discoverTools } from "./tools/discover.js";
import { cookieTools } from "./tools/cookies.js";
import { usernameTools } from "./tools/username.js";
import { vuln2Tools } from "./tools/vuln2.js";
import { reconTools } from "./tools/recon.js";
import { browser2Tools } from "./tools/browser2.js";
import { cryptoTools } from "./tools/crypto.js";
import { wsTools } from "./tools/websocket.js";
import { reportTools } from "./tools/report.js";
import { exploitTools } from "./tools/exploit.js";
import { browser3Tools } from "./tools/browser3.js";
import { liveViewTools } from "./tools/liveview.js";
import { swarmTools } from "./tools/swarm.js";
import { searchTools } from "./tools/search.js";
import { extractTools } from "./tools/extract.js";
import { aiTextTools } from "./tools/aitext.js";
import { dataTools } from "./tools/data.js";
import { osintTools } from "./tools/osint.js";
import { devUtilTools } from "./tools/devutil.js";
import { hub } from "./browser.js";
import type { ToolDef } from "./types.js";

const ALL: ToolDef[] = [
  ...browserTools,
  ...browser2Tools,
  ...browser3Tools,
  ...liveViewTools,
  ...consoleTools,
  ...sourceTools,
  ...discoverTools,
  ...apiTools,
  ...networkTools,
  ...scanTools,
  ...vulnTools,
  ...vuln2Tools,
  ...exploitTools,
  ...reconTools,
  ...cookieTools,
  ...usernameTools,
  ...wsTools,
  ...cryptoTools,
  ...userscriptTools,
  ...reportTools,
  ...swarmTools,
  ...searchTools,
  ...extractTools,
  ...aiTextTools,
  ...dataTools,
  ...osintTools,
  ...devUtilTools,
  ...utilTools,
];
const byName = new Map(ALL.map((t) => [t.name, t]));
const VERSION = "0.1.0";

const argv = process.argv.slice(2);
if (argv.includes("--version") || argv.includes("-v")) {
  console.log(VERSION); process.exit(0);
}
if (argv.includes("--help") || argv.includes("-h")) {
  console.log(`browser-mcp v${VERSION}
Browser-driven MCP server with ${ALL.length} tools:
  - browser control (navigate, click, type, screenshot, cookies, headers)
  - console paste + capture (console_eval, console_inject_script, console_get_logs)
  - source viewing (list scripts/stylesheets, fetch, grep across captured bodies)
  - network capture + replay + fuzz + HAR export
  - vulnerability scanners (headers, XSS, SQLi, open-redirect, JWT, CORS, forms, takeover, directory, full)
  - tampermonkey builder (userscript_build, userscript_from_console_eval)
  - utilities (http_request, base64, url_codec, hash)

Usage:
  browser-mcp                       run as MCP server over stdio
  browser-mcp --list-tools          print the tool names and exit
  browser-mcp --version | --help

Add to Claude Code:
  claude mcp add browser-mcp -- browser-mcp
or edit your MCP config:
  { "command": "browser-mcp", "args": [] }
`);
  process.exit(0);
}
if (argv.includes("--list-tools")) {
  for (const t of ALL) console.log(`${t.name.padEnd(32)}  ${t.description.split("\n")[0].slice(0, 110)}`);
  process.exit(0);
}

const server = new Server(
  { name: "browser-mcp", version: VERSION },
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
console.error(`browser-mcp v${VERSION} ready — ${ALL.length} tools registered`);
