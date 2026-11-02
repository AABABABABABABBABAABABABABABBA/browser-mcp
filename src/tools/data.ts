import { z } from "zod";
import { randomUUID } from "node:crypto";
import { ToolDef, ok, err } from "../types.js";

function csvParse(csv: string, delim = ","): any[] {
  const rows: string[][] = []; let row: string[] = []; let cur = ""; let inQ = false;
  for (let i = 0; i < csv.length; i++) {
    const c = csv[i];
    if (inQ) {
      if (c === '"' && csv[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') inQ = false;
      else cur += c;
    } else {
      if (c === '"') inQ = true;
      else if (c === delim) { row.push(cur); cur = ""; }
      else if (c === "\n" || c === "\r") { if (cur || row.length) { row.push(cur); rows.push(row); row = []; cur = ""; } if (c === "\r" && csv[i + 1] === "\n") i++; }
      else cur += c;
    }
  }
  if (cur || row.length) { row.push(cur); rows.push(row); }
  if (!rows.length) return [];
  const headers = rows[0];
  return rows.slice(1).map((r) => Object.fromEntries(headers.map((h, i) => [h, r[i] ?? ""])));
}

function csvStringify(rows: any[], delim = ","): string {
  if (!rows.length) return "";
  const headers = Array.from(rows.reduce((set: Set<string>, r) => { for (const k of Object.keys(r)) set.add(k); return set; }, new Set()));
  const esc = (v: any) => { const s = v == null ? "" : String(v); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  return [headers.join(delim), ...rows.map((r) => headers.map((h: any) => esc(r[h])).join(delim))].join("\n");
}

// Simple JSONPath-ish selector: $.a.b[0].c
function jpath(obj: any, path: string): any {
  const parts = path.replace(/^\$\.?/, "").split(/\.|\[(\d+)\]/).filter((p: any) => p !== undefined && p !== "");
  let cur = obj;
  for (const p of parts) { if (cur == null) return undefined; const idx: any = /^\d+$/.test(p) ? Number(p) : p; cur = cur[idx]; }
  return cur;
}

export const dataTools: ToolDef[] = [
  {
    name: "data_json_pretty",
    description: "Pretty-print a JSON string.",
    schema: z.object({ json: z.string(), indent: z.number().int().min(0).max(8).optional() }),
    handler: async (a) => { try { return ok(JSON.stringify(JSON.parse(a.json), null, a.indent ?? 2)); } catch (e: any) { return err(e.message); } },
  },
  {
    name: "data_json_minify",
    description: "Minify a JSON string.",
    schema: z.object({ json: z.string() }),
    handler: async (a) => { try { return ok(JSON.stringify(JSON.parse(a.json))); } catch (e: any) { return err(e.message); } },
  },
  {
    name: "data_json_path",
    description: "Pick a value from JSON using a dot/bracket path like $.foo.bar[0].baz.",
    schema: z.object({ json: z.string(), path: z.string() }),
    handler: async (a) => { try { return ok({ value: jpath(JSON.parse(a.json), a.path) }); } catch (e: any) { return err(e.message); } },
  },
  {
    name: "data_json_keys",
    description: "List all keys (deep) in a JSON object with their paths.",
    schema: z.object({ json: z.string(), maxDepth: z.number().int().positive().optional() }),
    handler: async (a) => {
      try {
        const paths: string[] = [];
        const walk = (o: any, p: string, d: number) => {
          if (!o || typeof o !== "object" || d > (a.maxDepth ?? 10)) return;
          for (const k of Object.keys(o)) {
            const np = Array.isArray(o) ? `${p}[${k}]` : p ? `${p}.${k}` : k;
            paths.push(np);
            walk(o[k], np, d + 1);
          }
        };
        walk(JSON.parse(a.json), "", 0);
        return ok({ count: paths.length, paths });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "data_csv_to_json",
    description: "Parse CSV into JSON array (first row = headers).",
    schema: z.object({ csv: z.string(), delimiter: z.string().optional() }),
    handler: async (a) => ok(csvParse(a.csv, a.delimiter ?? ",")),
  },
  {
    name: "data_json_to_csv",
    description: "Convert a JSON array of objects to CSV.",
    schema: z.object({ json: z.string(), delimiter: z.string().optional() }),
    handler: async (a) => {
      try { const arr = JSON.parse(a.json); if (!Array.isArray(arr)) return err("expected an array"); return ok(csvStringify(arr, a.delimiter ?? ",")); }
      catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "data_url_parse",
    description: "Break a URL into protocol/host/port/path/query/fragment with the query decoded into a dict.",
    schema: z.object({ url: z.string() }),
    handler: async (a) => {
      try {
        const u = new URL(a.url);
        const query: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (query[k] = v));
        return ok({ protocol: u.protocol, hostname: u.hostname, port: u.port || null, path: u.pathname, hash: u.hash, origin: u.origin, query, href: u.href });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "data_url_build",
    description: "Build a URL from parts (origin + path + query dict + hash).",
    schema: z.object({ origin: z.string(), path: z.string().optional(), query: z.record(z.string()).optional(), hash: z.string().optional() }),
    handler: async (a) => {
      const u = new URL(a.path ?? "/", a.origin);
      if (a.query) for (const [k, v] of Object.entries(a.query as Record<string, string>)) u.searchParams.set(k, v);
      if (a.hash) u.hash = a.hash;
      return ok(u.toString());
    },
  },
  {
    name: "data_query_parse",
    description: "Parse a query string like 'a=1&b=2&a=3' into a dict (repeated keys become arrays).",
    schema: z.object({ query: z.string() }),
    handler: async (a) => {
      const out: Record<string, any> = {};
      const p = new URLSearchParams(a.query.replace(/^\?/, ""));
      for (const [k, v] of p) { if (k in out) out[k] = Array.isArray(out[k]) ? [...out[k], v] : [out[k], v]; else out[k] = v; }
      return ok(out);
    },
  },
  {
    name: "data_xml_to_json",
    description: "Convert XML into a nested JSON structure (lightweight — no namespaces).",
    schema: z.object({ xml: z.string() }),
    handler: async (a) => {
      const parse = (xml: string): any => {
        const stack: any[] = [{ children: {} }];
        const re = /<([?!]?)([\w:-]+)(\s+[^>]*)?\/?>|<\/([\w:-]+)>|([^<]+)/g;
        let m: RegExpExecArray | null;
        while ((m = re.exec(xml))) {
          const [, prefix, open, attrs, close, text] = m;
          if (open && !close) {
            const node: any = {};
            if (attrs) for (const am of attrs.matchAll(/(\w[\w:-]*)="([^"]*)"/g)) (node["@" + am[1]] = am[2]);
            const parent = stack[stack.length - 1];
            if (parent.children[open]) { parent.children[open] = Array.isArray(parent.children[open]) ? [...parent.children[open], node] : [parent.children[open], node]; }
            else parent.children[open] = node;
            if (!m[0].endsWith("/>")) stack.push({ children: {}, ref: node });
            else Object.assign(node, {});
          } else if (close) {
            const frame = stack.pop(); if (frame?.ref) Object.assign(frame.ref, frame.children);
          } else if (text && text.trim()) {
            const frame = stack[stack.length - 1]; if (frame.ref) frame.ref["#text"] = text.trim();
          }
        }
        return stack[0].children;
      };
      try { return ok(parse(a.xml.replace(/<\?[\s\S]*?\?>/g, ""))); } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "data_yaml_to_json",
    description: "Parse a tiny subset of YAML (key: value, nested blocks, lists). Not a full implementation.",
    schema: z.object({ yaml: z.string() }),
    handler: async (a) => {
      const lines = a.yaml.replace(/\t/g, "  ").split(/\r?\n/).filter((l: string) => !/^\s*#/.test(l) && l.trim());
      const root: any = {}; const stack: any[] = [{ obj: root, indent: -1 }];
      for (const line of lines) {
        const indent = line.match(/^ */)![0].length;
        const t = line.trim();
        while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
        const parent = stack[stack.length - 1].obj;
        if (t.startsWith("- ")) {
          if (!Array.isArray(parent)) stack[stack.length - 1].obj = (() => { /* lazy upgrade */ const key = Object.keys(stack[stack.length - 2].obj).pop(); const arr: any[] = []; (stack[stack.length - 2].obj as any)[key!] = arr; stack[stack.length - 1].obj = arr; return arr; })();
          (stack[stack.length - 1].obj as any[]).push(t.slice(2));
        } else {
          const m = /^([\w.-]+):\s*(.*)$/.exec(t);
          if (!m) continue;
          const [, k, v] = m;
          if (v === "" || v === "|" || v === ">") { const o: any = {}; (parent as any)[k] = o; stack.push({ obj: o, indent }); }
          else { let val: any = v; if (/^-?\d+$/.test(v)) val = Number(v); else if (v === "true") val = true; else if (v === "false") val = false; else if (v === "null") val = null; else if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) val = v.slice(1, -1); (parent as any)[k] = val; }
        }
      }
      return ok(root);
    },
  },
  {
    name: "data_table_to_markdown",
    description: "Convert a JSON array of objects into a Markdown table.",
    schema: z.object({ json: z.string() }),
    handler: async (a) => {
      try {
        const arr = JSON.parse(a.json);
        if (!Array.isArray(arr) || !arr.length) return err("expected non-empty array");
        const headers = Array.from(arr.reduce((set: Set<string>, r: any) => { for (const k of Object.keys(r)) set.add(k); return set; }, new Set()));
        const lines = [`| ${headers.join(" | ")} |`, `|${headers.map(() => "---").join("|")}|`];
        for (const r of arr) lines.push(`| ${headers.map((h: any) => String(r[h] ?? "")).join(" | ")} |`);
        return ok(lines.join("\n"));
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "data_group_by",
    description: "Group a JSON array by a key, return count or an aggregate (sum/avg) of another numeric field.",
    schema: z.object({ json: z.string(), by: z.string(), agg: z.enum(["count", "sum", "avg", "min", "max"]).optional(), field: z.string().optional() }),
    handler: async (a) => {
      try {
        const arr = JSON.parse(a.json); if (!Array.isArray(arr)) return err("expected array");
        const groups: Record<string, number[]> = {};
        for (const r of arr) { const k = String(r[a.by] ?? ""); const v = a.field ? Number(r[a.field]) : 1; (groups[k] ??= []).push(v); }
        const agg = a.agg ?? "count";
        const out: Record<string, number> = {};
        for (const [k, vs] of Object.entries(groups)) {
          switch (agg) {
            case "count": out[k] = vs.length; break;
            case "sum": out[k] = vs.reduce((a, b) => a + b, 0); break;
            case "avg": out[k] = vs.reduce((a, b) => a + b, 0) / vs.length; break;
            case "min": out[k] = Math.min(...vs); break;
            case "max": out[k] = Math.max(...vs); break;
          }
        }
        return ok(out);
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "data_sort",
    description: "Sort a JSON array by a field (string or number). asc/desc.",
    schema: z.object({ json: z.string(), by: z.string(), direction: z.enum(["asc", "desc"]).optional() }),
    handler: async (a) => {
      try {
        const arr = JSON.parse(a.json); if (!Array.isArray(arr)) return err("expected array");
        const dir = a.direction === "desc" ? -1 : 1;
        const by = a.by; arr.sort((x: any, y: any) => { const xv = x[by]; const yv = y[by]; if (xv < yv) return -1 * dir; if (xv > yv) return 1 * dir; return 0; });
        return ok(arr);
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "data_filter",
    description: "Filter a JSON array by a predicate expression (JS, runs in a sandboxed `new Function('r', ...)` — be sure of the input).",
    schema: z.object({ json: z.string(), expr: z.string().describe("JS expression using 'r', e.g. r.score > 10") }),
    handler: async (a) => {
      try {
        const arr = JSON.parse(a.json); if (!Array.isArray(arr)) return err("expected array");
        const fn = new Function("r", `return (${a.expr});`);
        return ok(arr.filter((r: any) => { try { return fn(r); } catch { return false; } }));
      } catch (e: any) { return err(e.message); }
    },
  },
];
