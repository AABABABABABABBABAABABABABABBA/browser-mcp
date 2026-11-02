import { z } from "zod";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { ToolDef, ok, err } from "../types.js";

interface Finding { severity: "high" | "medium" | "low" | "info"; title: string; detail?: string; url?: string; evidence?: string; category?: string; ts: number; }
const store: Finding[] = [];

export const reportTools: ToolDef[] = [
  {
    name: "findings_add",
    description: "Add a finding to the session's accumulator. Use when a tool uncovers something worth reporting but didn't push it to the store itself.",
    schema: z.object({
      severity: z.enum(["high", "medium", "low", "info"]),
      title: z.string(),
      detail: z.string().optional(),
      url: z.string().optional(),
      evidence: z.string().optional(),
      category: z.string().optional(),
    }),
    handler: async (a) => { store.push({ ts: Date.now(), ...a }); return ok({ total: store.length }); },
  },
  {
    name: "findings_add_bulk",
    description: "Add many findings at once (e.g. the output of scan_api_keys, scan_full, deep_scan, etc.).",
    schema: z.object({
      findings: z.array(z.object({
        severity: z.enum(["high", "medium", "low", "info"]),
        title: z.string(),
        detail: z.string().optional(),
        url: z.string().optional(),
        evidence: z.string().optional(),
        category: z.string().optional(),
      })),
    }),
    handler: async (a) => { for (const f of a.findings) store.push({ ts: Date.now(), ...f }); return ok({ added: a.findings.length, total: store.length }); },
  },
  {
    name: "findings_list",
    description: "List accumulated findings, filterable by severity, category, or substring.",
    schema: z.object({ severity: z.enum(["high", "medium", "low", "info"]).optional(), category: z.string().optional(), q: z.string().optional() }),
    handler: async (a) => {
      let out = store.slice();
      if (a.severity) out = out.filter((f) => f.severity === a.severity);
      if (a.category) out = out.filter((f) => f.category === a.category);
      if (a.q) { const re = new RegExp(a.q, "i"); out = out.filter((f) => re.test(f.title) || re.test(f.detail ?? "")); }
      return ok({ count: out.length, findings: out });
    },
  },
  {
    name: "findings_clear",
    description: "Clear the findings store.",
    schema: z.object({}),
    handler: async () => { store.length = 0; return ok("cleared"); },
  },
  {
    name: "report_markdown",
    description: "Render accumulated findings as a Markdown pentest report, grouped by severity. Returns the text and optionally writes to a path.",
    schema: z.object({ title: z.string().optional(), target: z.string().optional(), savePath: z.string().optional() }),
    handler: async (a) => {
      const groups = { high: [] as Finding[], medium: [] as Finding[], low: [] as Finding[], info: [] as Finding[] };
      for (const f of store) groups[f.severity].push(f);
      const lines: string[] = [];
      lines.push(`# ${a.title ?? "Security Assessment Report"}`);
      if (a.target) lines.push(`\n**Target:** ${a.target}`);
      lines.push(`\n**Generated:** ${new Date().toISOString()}`);
      lines.push(`\n## Summary\n`);
      lines.push(`| Severity | Count |`); lines.push(`|---|---|`);
      lines.push(`| High | ${groups.high.length} |`);
      lines.push(`| Medium | ${groups.medium.length} |`);
      lines.push(`| Low | ${groups.low.length} |`);
      lines.push(`| Info | ${groups.info.length} |`);
      for (const sev of ["high", "medium", "low", "info"] as const) {
        if (!groups[sev].length) continue;
        lines.push(`\n## ${sev[0].toUpperCase() + sev.slice(1)} (${groups[sev].length})\n`);
        for (const f of groups[sev]) {
          lines.push(`### ${f.title}`);
          if (f.category) lines.push(`*Category: ${f.category}*`);
          if (f.url) lines.push(`**URL:** \`${f.url}\``);
          if (f.detail) lines.push(`\n${f.detail}`);
          if (f.evidence) lines.push("\n```\n" + f.evidence.slice(0, 2000) + "\n```");
          lines.push("");
        }
      }
      const md = lines.join("\n");
      if (a.savePath) { const p = resolve(a.savePath); await writeFile(p, md, "utf8"); return ok({ path: p, bytes: md.length, markdown: md }); }
      return ok({ markdown: md });
    },
  },
  {
    name: "report_json",
    description: "Export accumulated findings as structured JSON.",
    schema: z.object({ savePath: z.string().optional() }),
    handler: async (a) => {
      const body = JSON.stringify({ generated: new Date().toISOString(), count: store.length, findings: store }, null, 2);
      if (a.savePath) { const p = resolve(a.savePath); await writeFile(p, body, "utf8"); return ok({ path: p, bytes: body.length }); }
      return ok(body);
    },
  },
];
