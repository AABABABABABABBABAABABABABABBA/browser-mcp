import { z } from "zod";
import { randomUUID } from "node:crypto";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

type Severity = "high" | "medium" | "low" | "info";
interface SwarmFinding { severity: Severity; title: string; detail?: string; url?: string; evidence?: string; worker: string; }

interface SubAgent {
  id: string;
  name: string;
  status: "running" | "done" | "error" | "cancelled";
  sessionId?: string;
  startedAt: number;
  finishedAt?: number;
  findings: SwarmFinding[];
  logs: string[];
  error?: string;
  elapsedMs?: number;
  cancelSignal: { cancelled: boolean };
}

const agents = new Map<string, SubAgent>();

async function tool(name: string): Promise<{ handler: (args: any) => Promise<any> } | null> {
  // Dynamic imports to avoid circular churn
  const modules = await Promise.all([
    import("./scan.js").then((m) => m.scanTools),
    import("./vuln.js").then((m) => m.vulnTools),
    import("./vuln2.js").then((m) => m.vuln2Tools),
    import("./api.js").then((m) => m.apiTools),
    import("./recon.js").then((m) => m.reconTools),
    import("./discover.js").then((m) => m.discoverTools),
    import("./exploit.js").then((m) => m.exploitTools),
  ]);
  for (const list of modules) { const t = list.find((t: any) => t.name === name); if (t) return t; }
  return null;
}

function toFinding(worker: string, raw: any, defaultTitle?: string): SwarmFinding | null {
  if (!raw) return null;
  const severity: Severity = (raw.severity ?? "medium");
  const title = raw.title ?? raw.type ?? raw.engine ?? defaultTitle ?? "Finding";
  return {
    worker, severity, title,
    detail: raw.detail ?? raw.note ?? raw.payload ?? raw.file ?? undefined,
    url: raw.url ?? raw.path ?? undefined,
    evidence: raw.snippet ?? raw.context ?? raw.match ?? raw.found ?? undefined,
  };
}

function parseJsonFromTool(res: any): any {
  const text = res?.content?.[0]?.type === "text" ? res.content[0].text : "{}";
  try { return JSON.parse(text); } catch { return {}; }
}

async function runWorker(agent: SubAgent, url: string, worker: string, options: any = {}): Promise<SwarmFinding[]> {
  const s = await hub.openSession();
  agent.sessionId = s.id;
  agent.logs.push(`spawned session ${s.id}`);
  try {
    try { await s.page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 }); agent.logs.push(`navigated to ${url}`); } catch (e: any) { agent.logs.push(`nav failed: ${e.message}`); }
    if (agent.cancelSignal.cancelled) throw new Error("cancelled");

    const findings: SwarmFinding[] = [];
    const callTool = async (name: string, args: any) => {
      const t = await tool(name); if (!t) { agent.logs.push(`unknown tool ${name}`); return null; }
      const start = Date.now();
      const r = await t.handler({ ...args, sessionId: s.id });
      agent.logs.push(`${name} in ${Date.now() - start}ms`);
      return parseJsonFromTool(r);
    };

    switch (worker) {
      case "headers_cookies": {
        const h = await callTool("scan_headers", { url });
        for (const f of h?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        const c = await callTool("scan_cookies", {});
        for (const f of c?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        const cj = await callTool("scan_clickjacking", { url });
        for (const f of cj?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        break;
      }
      case "outdated_software": {
        const r = await callTool("scan_outdated", {});
        for (const f of r?.findings ?? []) { const ff = toFinding(worker, { ...f, title: f.title }); if (ff) findings.push(ff); }
        break;
      }
      case "api_keys": {
        const r = await callTool("scan_api_keys", {});
        for (const f of r?.findings ?? []) { const ff = toFinding(worker, { ...f, title: `Secret: ${f.type}` }); if (ff) findings.push(ff); }
        break;
      }
      case "sensitive_files": {
        const r = await callTool("scan_sensitive_files", { baseUrl: new URL(url).origin });
        for (const f of r?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        break;
      }
      case "injection_params": {
        // Discover query params on the page's URL and on any form, probe them
        const u = new URL(url);
        const params: Array<{ loc: "query"; name: string }> = Array.from(u.searchParams.keys()).map((k) => ({ loc: "query" as const, name: k }));
        if (!params.length) {
          agent.logs.push("no query params to fuzz; skipping injection probes");
          break;
        }
        for (const p of params) {
          if (agent.cancelSignal.cancelled) break;
          for (const scan of ["scan_xss_reflected", "scan_sqli", "scan_ssti", "scan_lfi", "scan_open_redirect"] as const) {
            const r = await callTool(scan, { url, param: p.name });
            for (const f of r?.findings ?? []) { const ff = toFinding(`${worker}:${scan}`, f); if (ff) findings.push(ff); }
          }
        }
        break;
      }
      case "dom_and_pp": {
        const r1 = await callTool("scan_dom_xss", {});
        for (const f of r1?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        const r2 = await callTool("scan_prototype_pollution", {});
        for (const f of r2?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        break;
      }
      case "recon_dns_subs": {
        const host = new URL(url).hostname;
        if (host === "127.0.0.1" || host === "localhost") { agent.logs.push("skipping recon on localhost"); break; }
        const parts = host.split("."); const apex = parts.slice(-2).join(".");
        const dns = await callTool("recon_dns", { host });
        if (dns) findings.push({ worker, severity: "info", title: `DNS: ${JSON.stringify(dns).slice(0, 180)}` });
        const subs = await callTool("recon_subdomains_dns", { domain: apex, concurrency: 15 });
        if (subs?.found?.length) findings.push({ worker, severity: "info", title: `Found ${subs.found.length} subdomains`, detail: subs.found.map((s: any) => s.host).join(", ").slice(0, 500) });
        break;
      }
      case "tech_waf_cms": {
        const r1 = await callTool("scan_tech_fingerprint", {});
        if (r1?.tech && Object.keys(r1.tech).length) findings.push({ worker, severity: "info", title: `Tech: ${JSON.stringify(r1.tech)}` });
        const r2 = await callTool("recon_waf", { url });
        if (r2?.detected?.length) findings.push({ worker, severity: "info", title: `WAF: ${r2.detected.map((d: any) => d.name).join(", ")}` });
        const r3 = await callTool("recon_cms", { baseUrl: new URL(url).origin });
        if (r3?.detected?.length) findings.push({ worker, severity: "info", title: `CMS: ${r3.detected.map((d: any) => d.cms).join(", ")}` });
        break;
      }
      case "debug_panels": {
        const r = await callTool("exploit_debug_panels", { baseUrl: new URL(url).origin });
        for (const f of r?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        break;
      }
      case "sourcemaps": {
        const r = await callTool("exploit_sourcemap_dump", {});
        if (r?.maps?.length) {
          const withContent = r.maps.filter((m: any) => m.withContent > 0).length;
          if (withContent > 0) findings.push({ worker, severity: "medium", title: `${withContent} source map(s) expose original source`, detail: r.maps.filter((m: any) => m.withContent).map((m: any) => m.scriptUrl).join("\n") });
        }
        break;
      }
      case "methods_ratelimit": {
        const r1 = await callTool("scan_methods", { url });
        for (const f of r1?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        const r2 = await callTool("scan_rate_limit", { url, count: 15, concurrency: 5 });
        for (const f of r2?.findings ?? []) { const ff = toFinding(worker, f); if (ff) findings.push(ff); }
        break;
      }
    }
    return findings;
  } finally {
    try { await hub.closeSession(agent.sessionId); } catch { /* pumppet */ }
  }
}

const WORKER_NAMES = [
  "headers_cookies",
  "outdated_software",
  "api_keys",
  "sensitive_files",
  "injection_params",
  "dom_and_pp",
  "recon_dns_subs",
  "tech_waf_cms",
  "debug_panels",
  "sourcemaps",
  "methods_ratelimit",
] as const;

const DEFAULT_WORKERS: Array<typeof WORKER_NAMES[number]> = [
  "headers_cookies", "outdated_software", "api_keys", "sensitive_files",
  "injection_params", "dom_and_pp", "tech_waf_cms", "sourcemaps",
];

export const swarmTools: ToolDef[] = [
  {
    name: "swarm_scan",
    description: "Spawn 5+ parallel sub-agents, each in its own browser session, each running a different family of scans on the target. Returns right away with agent IDs. Call swarm_wait or sub_agent_list to collect. Default worker set is 8 workers covering: headers+cookies, outdated-software, API-keys/secrets, sensitive-files, param-injection (XSS/SQLi/SSTI/LFI/open-redirect), DOM-XSS+prototype-pollution, tech+WAF+CMS, sourcemaps. Pass workers=['...'] to pick a subset or add 'recon_dns_subs','debug_panels','methods_ratelimit'.",
    schema: z.object({
      url: z.string().url(),
      workers: z.array(z.enum(WORKER_NAMES)).optional(),
      autoWait: z.boolean().optional().describe("if true, blocks until all workers finish and returns the aggregated findings"),
      waitTimeoutMs: z.number().int().positive().optional(),
    }),
    handler: async (a) => {
      const names = a.workers ?? DEFAULT_WORKERS;
      const ids: string[] = [];
      for (const name of names) {
        const id = randomUUID().slice(0, 6);
        const agent: SubAgent = { id, name, status: "running", startedAt: Date.now(), findings: [], logs: [], cancelSignal: { cancelled: false } };
        agents.set(id, agent);
        (async () => {
          try {
            const results = await runWorker(agent, a.url, name);
            agent.findings.push(...results);
            agent.status = "done";
          } catch (e: any) {
            agent.status = agent.cancelSignal.cancelled ? "cancelled" : "error";
            agent.error = e?.message ?? String(e);
          } finally {
            agent.finishedAt = Date.now();
            agent.elapsedMs = agent.finishedAt - agent.startedAt;
          }
        })();
        ids.push(id);
      }
      if (!a.autoWait) {
        return ok({ spawned: ids.length, agents: ids.map((id) => ({ id, worker: agents.get(id)!.name })), note: "running in background — call swarm_wait or sub_agent_list" });
      }
      const timeout = a.waitTimeoutMs ?? 180000;
      const deadline = Date.now() + timeout;
      while (ids.some((id) => agents.get(id)!.status === "running") && Date.now() < deadline) await new Promise((r) => setTimeout(r, 300));
      const list = ids.map((id) => agents.get(id)!);
      const allFindings = list.flatMap((a) => a.findings);
      const summary = { high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>;
      for (const f of allFindings) summary[f.severity] = (summary[f.severity] ?? 0) + 1;
      return ok({
        spawned: ids.length, completed: list.filter((a) => a.status === "done").length,
        errors: list.filter((a) => a.status === "error").map((a) => ({ worker: a.name, error: a.error })),
        summary, totalFindings: allFindings.length,
        workers: list.map((a) => ({ id: a.id, worker: a.name, status: a.status, elapsedMs: a.elapsedMs, findings: a.findings.length })),
        findings: allFindings,
      });
    },
  },
  {
    name: "swarm_wait",
    description: "Wait for the running swarm agents to finish; return the aggregated findings.",
    schema: z.object({
      ids: z.array(z.string()).optional().describe("agent ids to wait on; defaults to every currently running agent"),
      timeoutMs: z.number().int().positive().optional(),
    }),
    handler: async (a) => {
      const ids: string[] = a.ids ?? Array.from(agents.values()).filter((x) => x.status === "running").map((x) => x.id);
      const deadline = Date.now() + (a.timeoutMs ?? 180000);
      while (ids.some((id: string) => agents.get(id)?.status === "running") && Date.now() < deadline) await new Promise((r) => setTimeout(r, 300));
      const list = ids.map((id: string) => agents.get(id)!).filter(Boolean);
      const allFindings = list.flatMap((a: SubAgent) => a.findings);
      const summary = { high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>;
      for (const f of allFindings) summary[f.severity] = (summary[f.severity] ?? 0) + 1;
      return ok({ waited: list.length, stillRunning: ids.filter((id: string) => agents.get(id)?.status === "running").length, summary, totalFindings: allFindings.length, findings: allFindings });
    },
  },
  {
    name: "sub_agent_list",
    description: "List all sub-agents and their status.",
    schema: z.object({ status: z.enum(["running", "done", "error", "cancelled"]).optional() }),
    handler: async (a) => {
      let out = Array.from(agents.values());
      if (a.status) out = out.filter((x) => x.status === a.status);
      return ok(out.map((x) => ({ id: x.id, worker: x.name, status: x.status, startedAt: x.startedAt, elapsedMs: x.elapsedMs, findings: x.findings.length, error: x.error })));
    },
  },
  {
    name: "sub_agent_get",
    description: "Get a single sub-agent's full state including logs and findings.",
    schema: z.object({ id: z.string() }),
    handler: async (a) => {
      const g = agents.get(a.id); if (!g) return err(`no agent ${a.id}`);
      return ok({ id: g.id, worker: g.name, status: g.status, startedAt: g.startedAt, elapsedMs: g.elapsedMs, sessionId: g.sessionId, error: g.error, logs: g.logs, findings: g.findings });
    },
  },
  {
    name: "sub_agent_cancel",
    description: "Cancel a running sub-agent. The worker checks its cancel flag at step boundaries and bails out.",
    schema: z.object({ id: z.string() }),
    handler: async (a) => {
      const g = agents.get(a.id); if (!g) return err(`no agent ${a.id}`);
      g.cancelSignal.cancelled = true;
      return ok("cancellation requested");
    },
  },
  {
    name: "sub_agent_clear",
    description: "Remove done/errored sub-agents from the registry (keeps still-running ones).",
    schema: z.object({}),
    handler: async () => {
      let removed = 0;
      for (const [id, g] of agents.entries()) if (g.status !== "running") { agents.delete(id); removed++; }
      return ok({ removed, remaining: agents.size });
    },
  },
  {
    name: "sub_agent_spawn",
    description: "Spawn a custom sub-agent that runs an arbitrary sequence of tool calls in its own browser session, in parallel with others. Returns an agent id immediately. Each step is a {tool, args} record. If the tool returns findings, they're added to the agent. useOwnSession:true (default) creates an isolated session; false shares the default session.",
    schema: z.object({
      name: z.string(),
      steps: z.array(z.object({ tool: z.string(), args: z.record(z.any()).optional() })).min(1),
      useOwnSession: z.boolean().optional(),
      navigateTo: z.string().url().optional().describe("if useOwnSession, navigate here first"),
    }),
    handler: async (a) => {
      const id = randomUUID().slice(0, 6);
      const agent: SubAgent = { id, name: a.name, status: "running", startedAt: Date.now(), findings: [], logs: [], cancelSignal: { cancelled: false } };
      agents.set(id, agent);
      (async () => {
        try {
          let sid: string | undefined;
          if (a.useOwnSession !== false) {
            const s = await hub.openSession(); sid = s.id; agent.sessionId = sid; agent.logs.push(`session ${sid}`);
            if (a.navigateTo) { try { await s.page.goto(a.navigateTo, { waitUntil: "domcontentloaded", timeout: 20000 }); agent.logs.push(`navigated to ${a.navigateTo}`); } catch (e: any) { agent.logs.push(`nav fail: ${e.message}`); } }
          }
          for (const step of a.steps) {
            if (agent.cancelSignal.cancelled) throw new Error("cancelled");
            const t = await tool(step.tool);
            if (!t) { agent.logs.push(`unknown tool: ${step.tool}`); continue; }
            const start = Date.now();
            const r = await t.handler({ ...(step.args ?? {}), sessionId: sid ?? (step.args as any)?.sessionId });
            const parsed = parseJsonFromTool(r);
            agent.logs.push(`${step.tool} in ${Date.now() - start}ms`);
            for (const f of parsed?.findings ?? []) { const ff = toFinding(a.name, f); if (ff) agent.findings.push(ff); }
          }
          agent.status = "done";
        } catch (e: any) {
          agent.status = agent.cancelSignal.cancelled ? "cancelled" : "error";
          agent.error = e?.message ?? String(e);
        } finally {
          agent.finishedAt = Date.now();
          agent.elapsedMs = agent.finishedAt - agent.startedAt;
          if (agent.sessionId) try { await hub.closeSession(agent.sessionId); } catch { /* pumppet */ }
        }
      })();
      return ok({ id, name: a.name });
    },
  },
  {
    name: "swarm_pentest_report",
    description: "After swarm_scan completes, build a Markdown pentest report from every sub-agent's findings. Groups by severity + worker.",
    schema: z.object({ ids: z.array(z.string()).optional(), title: z.string().optional(), target: z.string().optional(), savePath: z.string().optional() }),
    handler: async (a) => {
      const list = (a.ids ?? Array.from(agents.keys())).map((id: string) => agents.get(id)!).filter(Boolean);
      const all = list.flatMap((a: SubAgent) => a.findings);
      const bySev: Record<string, SwarmFinding[]> = { high: [], medium: [], low: [], info: [] };
      for (const f of all) bySev[f.severity].push(f);
      const lines: string[] = [];
      lines.push(`# ${a.title ?? "Swarm Pentest Report"}`);
      if (a.target) lines.push(`\n**Target:** ${a.target}`);
      lines.push(`\n**Generated:** ${new Date().toISOString()}`);
      lines.push(`\n## Summary\n\n| Severity | Count |\n|---|---|`);
      for (const sev of ["high", "medium", "low", "info"] as const) lines.push(`| ${sev[0].toUpperCase() + sev.slice(1)} | ${bySev[sev].length} |`);
      lines.push(`\n## Workers\n\n| Worker | Status | Findings | Elapsed |\n|---|---|---|---|`);
      for (const w of list) lines.push(`| ${w.name} | ${w.status} | ${w.findings.length} | ${w.elapsedMs ?? "-"}ms |`);
      for (const sev of ["high", "medium", "low", "info"] as const) {
        if (!bySev[sev].length) continue;
        lines.push(`\n## ${sev[0].toUpperCase() + sev.slice(1)} (${bySev[sev].length})`);
        for (const f of bySev[sev]) {
          lines.push(`\n### [${f.worker}] ${f.title}`);
          if (f.url) lines.push(`**URL:** \`${f.url}\``);
          if (f.detail) lines.push(`\n${f.detail}`);
          if (f.evidence) lines.push("\n```\n" + f.evidence.slice(0, 1500) + "\n```");
        }
      }
      const md = lines.join("\n");
      if (a.savePath) { const { writeFile } = await import("node:fs/promises"); const { resolve } = await import("node:path"); const p = resolve(a.savePath); await writeFile(p, md, "utf8"); return ok({ path: p, bytes: md.length, markdown: md }); }
      return ok({ markdown: md });
    },
  },
];
