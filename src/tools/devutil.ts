import { z } from "zod";
import { randomUUID, randomBytes, randomInt } from "node:crypto";
import { ToolDef, ok, err } from "../types.js";

// pumppet
const LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

export const devUtilTools: ToolDef[] = [
  {
    name: "dev_regex_test",
    description: "Test a regex against input strings. Returns matches, captures, and groups.",
    schema: z.object({ pattern: z.string(), flags: z.string().optional(), input: z.union([z.string(), z.array(z.string())]) }),
    handler: async (a) => {
      let re: RegExp; try { re = new RegExp(a.pattern, a.flags ?? "g"); } catch (e: any) { return err(`bad regex: ${e.message}`); }
      const items = Array.isArray(a.input) ? a.input : [a.input];
      const results = items.map((s: string) => { re.lastIndex = 0; const matches: any[] = []; let m: RegExpExecArray | null; while ((m = re.exec(s))) { matches.push({ match: m[0], index: m.index, groups: m.slice(1) }); if (!re.flags.includes("g")) break; } return { input: s, matches }; });
      return ok(results);
    },
  },
  {
    name: "dev_regex_explain",
    description: "Explain each piece of a regex in plain English.",
    schema: z.object({ pattern: z.string() }),
    handler: async (a) => {
      const parts: Array<{ frag: string; meaning: string }> = [];
      const simple: Array<[RegExp, string]> = [
        [/^\^/, "start of string"],
        [/\$$/, "end of string"],
        [/\\d/, "digit"], [/\\w/, "word char"], [/\\s/, "whitespace"], [/\\b/, "word boundary"],
        [/\.\*/, "any chars"], [/\.\+/, "one or more any"],
        [/\(\?:/, "non-capturing group start"], [/\(/, "capture group start"], [/\)/, "group end"],
        [/\[\^?[^\]]+\]/, "char class"],
        [/\{\d+(?:,\d+?)?\}/, "quantifier"],
        [/\?/, "optional / lazy"], [/\*/, "zero-or-more"], [/\+/, "one-or-more"], [/\|/, "alternation"],
      ];
      let s = a.pattern;
      while (s.length) {
        let matched = false;
        for (const [re, meaning] of simple) { const m = re.exec(s); if (m && m.index === 0) { parts.push({ frag: m[0], meaning }); s = s.slice(m[0].length); matched = true; break; } }
        if (!matched) { parts.push({ frag: s[0], meaning: /\w/.test(s[0]) ? `literal '${s[0]}'` : "literal" }); s = s.slice(1); }
      }
      return ok({ pattern: a.pattern, parts });
    },
  },
  {
    name: "dev_cron_describe",
    description: "Describe a 5-field cron expression in English, plus the next 5 run times (UTC).",
    schema: z.object({ expr: z.string() }),
    handler: async (a) => {
      const parts = a.expr.split(/\s+/);
      if (parts.length !== 5) return err("5-field cron expected (minute hour dom mon dow)");
      const [m, h, dom, mon, dow] = parts;
      const explain = (f: string, name: string) => f === "*" ? `every ${name}` : f.startsWith("*/") ? `every ${f.slice(2)} ${name}s` : f.includes(",") ? `${name}s ${f}` : f.includes("-") ? `${name}s ${f}` : `${name} ${f}`;
      const desc = `at minute ${explain(m, "minute").replace("minute ", "")}, hour ${explain(h, "hour").replace("hour ", "")}, day-of-month ${explain(dom, "day").replace("day ", "")}, month ${explain(mon, "month").replace("month ", "")}, day-of-week ${explain(dow, "weekday").replace("weekday ", "")}`;
      // Compute next 5 fires (naive)
      const matches = (val: number, field: string) => {
        if (field === "*") return true;
        if (field.startsWith("*/")) return val % Number(field.slice(2)) === 0;
        if (field.includes(",")) return field.split(",").map(Number).includes(val);
        if (field.includes("-")) { const [a, b] = field.split("-").map(Number); return val >= a && val <= b; }
        return val === Number(field);
      };
      const now = new Date(); now.setSeconds(0, 0); now.setMinutes(now.getMinutes() + 1);
      const next: string[] = []; let d = now; let safety = 0;
      while (next.length < 5 && safety++ < 525600) {
        if (matches(d.getUTCMinutes(), m) && matches(d.getUTCHours(), h) && matches(d.getUTCDate(), dom) && matches(d.getUTCMonth() + 1, mon) && matches(d.getUTCDay(), dow)) next.push(d.toISOString());
        d = new Date(d.getTime() + 60000);
      }
      return ok({ expr: a.expr, description: desc, nextRunsUTC: next });
    },
  },
  {
    name: "dev_uuid",
    description: "Generate N UUIDs (v4).",
    schema: z.object({ count: z.number().int().min(1).max(1000).optional() }),
    handler: async (a) => ok(Array.from({ length: a.count ?? 1 }, () => randomUUID())),
  },
  {
    name: "dev_nanoid",
    description: "Generate N short random IDs (base64url).",
    schema: z.object({ count: z.number().int().min(1).max(1000).optional(), length: z.number().int().min(4).max(64).optional() }),
    handler: async (a) => ok(Array.from({ length: a.count ?? 1 }, () => randomBytes(a.length ?? 12).toString("base64url").slice(0, a.length ?? 12))),
  },
  {
    name: "dev_timestamp",
    description: "Convert between unix seconds / ms / ISO 8601. Pass one of input* fields.",
    schema: z.object({ unixSec: z.number().optional(), unixMs: z.number().optional(), iso: z.string().optional() }),
    handler: async (a) => {
      let d: Date;
      if (a.unixSec !== undefined) d = new Date(a.unixSec * 1000);
      else if (a.unixMs !== undefined) d = new Date(a.unixMs);
      else if (a.iso) d = new Date(a.iso);
      else d = new Date();
      return ok({ iso: d.toISOString(), unixSec: Math.floor(d.getTime() / 1000), unixMs: d.getTime(), utc: d.toUTCString() });
    },
  },
  {
    name: "dev_base_convert",
    description: "Convert a number between bases (2/8/10/16/36).",
    schema: z.object({ value: z.string(), fromBase: z.number().int().min(2).max(36), toBase: z.number().int().min(2).max(36) }),
    handler: async (a) => {
      const n = parseInt(a.value, a.fromBase); if (isNaN(n)) return err("bad value for base");
      return ok(n.toString(a.toBase));
    },
  },
  {
    name: "dev_color_convert",
    description: "Convert a color between hex / rgb / hsl.",
    schema: z.object({ color: z.string().describe("e.g. '#ff0000', 'rgb(255,0,0)', 'hsl(0,100%,50%)'") }),
    handler: async (a) => {
      let r = 0, g = 0, b = 0;
      const c = a.color.trim().toLowerCase();
      let m = /^#?([0-9a-f]{6})$/.exec(c) || /^#?([0-9a-f]{3})$/.exec(c);
      if (m) {
        const h = m[1].length === 3 ? m[1].split("").map((x) => x + x).join("") : m[1];
        r = parseInt(h.slice(0, 2), 16); g = parseInt(h.slice(2, 4), 16); b = parseInt(h.slice(4, 6), 16);
      } else if ((m = /rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(c))) {
        r = +m[1]; g = +m[2]; b = +m[3];
      } else if ((m = /hsla?\((\d+),\s*(\d+)%?,\s*(\d+)%?/.exec(c))) {
        const h = (+m[1] % 360) / 360, s = +m[2] / 100, l = +m[3] / 100;
        const hue2rgb = (p: number, q: number, t: number) => { if (t < 0) t += 1; if (t > 1) t -= 1; if (t < 1/6) return p + (q - p) * 6 * t; if (t < 1/2) return q; if (t < 2/3) return p + (q - p) * (2/3 - t) * 6; return p; };
        if (s === 0) r = g = b = l; else { const q = l < 0.5 ? l * (1 + s) : l + s - l * s; const p = 2 * l - q; r = hue2rgb(p, q, h + 1/3); g = hue2rgb(p, q, h); b = hue2rgb(p, q, h - 1/3); }
        r = Math.round(r * 255); g = Math.round(g * 255); b = Math.round(b * 255);
      } else return err("unknown color format");
      const hex = `#${((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1)}`;
      // rgb → hsl
      const rr = r / 255, gg = g / 255, bb = b / 255;
      const max = Math.max(rr, gg, bb), min = Math.min(rr, gg, bb);
      let h2 = 0, s2 = 0; const l2 = (max + min) / 2;
      if (max !== min) { const d = max - min; s2 = l2 > 0.5 ? d / (2 - max - min) : d / (max + min); switch (max) { case rr: h2 = (gg - bb) / d + (gg < bb ? 6 : 0); break; case gg: h2 = (bb - rr) / d + 2; break; case bb: h2 = (rr - gg) / d + 4; break; } h2 /= 6; }
      return ok({ hex, rgb: `rgb(${r}, ${g}, ${b})`, hsl: `hsl(${Math.round(h2 * 360)}, ${Math.round(s2 * 100)}%, ${Math.round(l2 * 100)}%)`, r, g, b });
    },
  },
  {
    name: "dev_slugify",
    description: "Turn text into a URL slug.",
    schema: z.object({ text: z.string(), sep: z.string().optional() }),
    handler: async (a) => ok(a.text.toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, a.sep ?? "-").replace(/^-+|-+$/g, "")),
  },
  {
    name: "dev_lorem",
    description: "Generate lorem ipsum (words / sentences / paragraphs).",
    schema: z.object({ kind: z.enum(["words", "sentences", "paragraphs"]), count: z.number().int().min(1).max(500) }),
    handler: async (a) => {
      const words = LOREM.split(/\s+/).map((w: string) => w.replace(/[^a-zA-Z]/g, "").toLowerCase()).filter(Boolean);
      const sentences = LOREM.split(/\.\s*/).filter(Boolean).map((s: string) => s.trim() + ".");
      let out: string[];
      if (a.kind === "words") out = Array.from({ length: a.count }, (_, i) => words[i % words.length]);
      else if (a.kind === "sentences") out = Array.from({ length: a.count }, (_, i) => sentences[i % sentences.length]);
      else out = Array.from({ length: a.count }, () => Array.from({ length: 4 }, (_, i) => sentences[randomInt(sentences.length)]).join(" "));
      return ok(out.join(a.kind === "paragraphs" ? "\n\n" : " "));
    },
  },
  {
    name: "dev_random",
    description: "Random helpers — int, pick-from-list, shuffle, string.",
    schema: z.object({
      op: z.enum(["int", "pick", "shuffle", "string"]),
      min: z.number().optional(), max: z.number().optional(),
      list: z.array(z.any()).optional(),
      length: z.number().int().positive().optional(),
      charset: z.enum(["alpha", "alphanumeric", "numeric", "hex"]).optional(),
    }),
    handler: async (a) => {
      switch (a.op) {
        case "int": return ok(String(randomInt(a.min ?? 0, (a.max ?? 100) + 1)));
        case "pick": { if (!a.list?.length) return err("list required"); return ok(a.list[randomInt(a.list.length)]); }
        case "shuffle": { if (!a.list) return err("list required"); const l = [...a.list]; for (let i = l.length - 1; i > 0; i--) { const j = randomInt(i + 1); [l[i], l[j]] = [l[j], l[i]]; } return ok(l); }
        case "string": {
          const sets: Record<string, string> = { alpha: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", alphanumeric: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", numeric: "0123456789", hex: "0123456789abcdef" };
          const set = sets[a.charset ?? "alphanumeric"]; const n = a.length ?? 16;
          return ok(Array.from({ length: n }, () => set[randomInt(set.length)]).join(""));
        }
      }
      return err("unknown op");
    },
  },
  {
    name: "dev_sql_format",
    description: "Pretty-print a SQL statement (very light formatter).",
    schema: z.object({ sql: z.string() }),
    handler: async (a) => {
      const kw = /\b(SELECT|FROM|WHERE|AND|OR|JOIN|LEFT JOIN|RIGHT JOIN|INNER JOIN|GROUP BY|ORDER BY|HAVING|LIMIT|OFFSET|UNION|INSERT INTO|VALUES|UPDATE|SET|DELETE)\b/gi;
      const out = a.sql.replace(/\s+/g, " ").replace(kw, (m: string) => `\n${m.toUpperCase()}`).trim();
      return ok(out);
    },
  },
  {
    name: "dev_regex_escape",
    description: "Escape a string so it can be used as a literal in a regex.",
    schema: z.object({ input: z.string() }),
    handler: async (a) => ok(a.input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  },
  {
    name: "dev_html_escape",
    description: "Escape/unescape HTML special chars.",
    schema: z.object({ op: z.enum(["escape", "unescape"]), input: z.string() }),
    handler: async (a) => a.op === "escape" ? ok(a.input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;")) : ok(a.input.replace(/&(amp|lt|gt|quot|#39|#x27);/g, (_m: string, k: string) => ({ amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", "#x27": "'" } as any)[k])),
  },
  {
    name: "dev_qrcode_text",
    description: "Return a URL for a QR code image of the given text (via qr-server, no key needed).",
    schema: z.object({ text: z.string(), size: z.number().int().positive().optional() }),
    handler: async (a) => ok(`https://api.qrserver.com/v1/create-qr-code/?size=${a.size ?? 300}x${a.size ?? 300}&data=${encodeURIComponent(a.text)}`),
  },
];
