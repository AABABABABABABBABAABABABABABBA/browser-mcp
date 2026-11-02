import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

export const consoleTools: ToolDef[] = [
  {
    name: "console_eval",
    description: "Paste JavaScript into the page's console and get the result back. Handles async code with top-level await. Returns the serialized return value plus typeof and anything the code console.logged.",
    schema: z.object({
      code: z.string().describe("JS source. If it looks like an expression, its value is returned. If it's statements, use `return x;`."),
      timeoutMs: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const before = s.consoleLogs.length;
      const t = a.timeoutMs ?? 10000;
      try {
        const result = await Promise.race([
          s.page.evaluate(async (code) => {
            const trimmed = code.trim();
            // if there's no `return` anywhere and no block/statement starters, treat as an expression.
            const starters = /^(const\s|let\s|var\s|if\s*\(|for\s*\(|while\s*\(|do\s*\{|switch\s*\(|throw\s|try\s*\{|\{|function\s|class\s|async\s+function)/;
            const hasReturn = /\breturn\b/.test(trimmed);
            const looksLikeExpr = !hasReturn && !starters.test(trimmed);
            const body = looksLikeExpr ? `return (${trimmed});` : trimmed;
            const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
            const fn = new AsyncFunction(body);
            const v = await fn();
            const safe = (x: any): any => {
              if (x === null || x === undefined) return x;
              if (typeof x === "function") return `[Function ${x.name || "anonymous"}]`;
              if (typeof x !== "object") return x;
              if (x instanceof Error) return { __error: true, name: x.name, message: x.message, stack: x.stack };
              try { JSON.stringify(x); return x; } catch { return String(x); }
            };
            return { value: safe(v), typeOf: typeof v };
          }, a.code),
          new Promise((_, rj) => setTimeout(() => rj(new Error(`timeout after ${t}ms`)), t)),
        ]);
        const newLogs = s.consoleLogs.slice(before);
        return ok({ ...(result as any), logs: newLogs });
      } catch (e: any) {
        return err(`eval failed: ${e?.message ?? e}`);
      }
    },
  },
  {
    name: "console_get_logs",
    description: "Return captured console messages (log/warn/error/info/debug/dialog) from the session.",
    schema: z.object({
      type: z.string().optional().describe("filter by type substring, e.g. 'error'"),
      pattern: z.string().optional().describe("regex over message text"),
      limit: z.number().int().positive().optional(),
      includeErrors: z.boolean().optional().describe("also include uncaught pageerrors"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      let items: any[] = s.consoleLogs.slice();
      if (a.type) items = items.filter((e) => e.type.includes(a.type));
      if (a.pattern) { const re = new RegExp(a.pattern, "i"); items = items.filter((e) => re.test(e.text)); }
      if (a.limit) items = items.slice(-a.limit);
      const out: any = { logs: items };
      if (a.includeErrors !== false) out.pageErrors = s.pageErrors;
      return ok(out);
    },
  },
  {
    name: "console_clear_logs",
    description: "Clear the captured console log buffer.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      s.consoleLogs.length = 0;
      s.pageErrors.length = 0;
      return ok("cleared");
    },
  },
  {
    name: "console_inject_script",
    description: "Inject a <script> tag with the given source code into the current page. The script runs in the page's own context (not an isolated world), so it can touch page variables.",
    schema: z.object({ code: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.page.addScriptTag({ content: a.code });
      return ok("injected");
    },
  },
  {
    name: "console_prepend_init_script",
    description: "Register a script that runs on every new document/frame in this session BEFORE any page JS runs. Useful for monkey-patching, pre-setting storage, or installing hooks before a SPA boots.",
    schema: z.object({ code: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.context.addInitScript({ content: a.code });
      return ok("init script armed — reload or navigate for it to take effect");
    },
  },
];
