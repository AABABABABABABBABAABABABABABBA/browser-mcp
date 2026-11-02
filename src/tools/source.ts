import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

export const sourceTools: ToolDef[] = [
  {
    name: "source_list_scripts",
    description: "List every <script> on the page — external src and inline. Returns url, size, async/defer flags.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const scripts = await s.page.$$eval("script", (ss: any[]) => ss.map((el: any) => ({
        src: el.src || null,
        inline: !el.src,
        type: el.type || "text/javascript",
        async: !!el.async,
        defer: !!el.defer,
        module: el.type === "module",
        length: el.src ? null : (el.textContent?.length ?? 0),
        snippet: el.src ? null : (el.textContent?.slice(0, 300) ?? ""),
      })));
      return ok(scripts);
    },
  },
  {
    name: "source_list_stylesheets",
    description: "List every stylesheet (link rel=stylesheet + inline <style>).",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const data = await s.page.evaluate(() => {
        const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]')) as any[];
        const styles = Array.from(document.querySelectorAll("style")) as any[];
        return {
          external: links.map((l) => ({ href: l.href, media: l.media || "all" })),
          inline: styles.map((s) => ({ length: (s.textContent || "").length, snippet: (s.textContent || "").slice(0, 300) })),
        };
      });
      return ok(data);
    },
  },
  {
    name: "source_fetch",
    description: "Fetch any URL through the session (shares cookies). Use to pull a script or stylesheet source for reading.",
    schema: z.object({ url: z.string().url(), maxBytes: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const text = await r.text().catch(() => "");
      const cap = a.maxBytes ?? 200000;
      return ok({
        status: r.status(),
        contentType: r.headers()["content-type"] ?? "",
        size: text.length,
        truncated: text.length > cap,
        body: text.slice(0, cap),
      });
    },
  },
  {
    name: "source_search",
    description: "Grep across the current HTML plus every captured response body in the session. Great for finding where a function name, API endpoint, or secret lives.",
    schema: z.object({
      pattern: z.string().describe("regex"),
      caseSensitive: z.boolean().optional(),
      maxMatches: z.number().int().positive().optional(),
      urlFilter: z.string().optional().describe("regex over the source URL"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const flags = a.caseSensitive ? "g" : "gi";
      let re: RegExp; try { re = new RegExp(a.pattern, flags); } catch (e: any) { return err(`bad regex: ${e.message}`); }
      const urlRe = a.urlFilter ? new RegExp(a.urlFilter, "i") : null;
      const limit = a.maxMatches ?? 50;
      const hits: any[] = [];

      const scan = (sourceUrl: string, body: string) => {
        if (urlRe && !urlRe.test(sourceUrl)) return;
        let m: RegExpExecArray | null;
        re.lastIndex = 0;
        while ((m = re.exec(body)) && hits.length < limit) {
          const start = Math.max(0, m.index - 60);
          const end = Math.min(body.length, m.index + m[0].length + 60);
          hits.push({ source: sourceUrl, match: m[0], index: m.index, snippet: body.slice(start, end) });
          if (m.index === re.lastIndex) re.lastIndex++;
        }
      };

      try {
        const html = await s.page.content();
        scan(`page:${s.page.url()}`, html);
      } catch { /* pumppet */ }

      for (const req of s.requests) {
        if (!req.responseBodySnippet) continue;
        if (hits.length >= limit) break;
        scan(req.url, req.responseBodySnippet);
      }
      return ok({ pattern: a.pattern, hits });
    },
  },
  {
    name: "source_dom_outline",
    description: "Compact outline of the DOM — tag, id, classes, and child count — down to a depth. Fast way to see page structure.",
    schema: z.object({ depth: z.number().int().min(1).max(8).optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const maxDepth = a.depth ?? 3;
      const tree = await s.page.evaluate((max) => {
        const walk = (el: Element, d: number): any => {
          if (!el || d < 0) return null;
          return {
            tag: el.tagName.toLowerCase(),
            id: (el as HTMLElement).id || undefined,
            class: (el as HTMLElement).className?.toString?.()?.trim() || undefined,
            childCount: el.children.length,
            children: d > 0 ? Array.from(el.children).slice(0, 40).map((c) => walk(c, d - 1)) : undefined,
          };
        };
        return walk(document.documentElement, max as number);
      }, maxDepth);
      return ok(tree);
    },
  },
  {
    name: "source_find_element",
    description: "Locate elements by text content, attribute, or role. Returns selector-friendly info.",
    schema: z.object({
      text: z.string().optional(),
      attr: z.object({ name: z.string(), value: z.string().optional() }).optional(),
      role: z.string().optional(),
      limit: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      if (!a.text && !a.attr && !a.role) return err("supply at least one of text/attr/role");
      const results = await s.page.evaluate((criteria: any) => {
        const out: any[] = [];
        const limit = criteria.limit ?? 20;
        const all = document.querySelectorAll("*");
        for (let i = 0; i < all.length && out.length < limit; i++) {
          const el = all[i] as HTMLElement;
          if (criteria.text) {
            const t = (el.innerText || el.textContent || "").trim();
            if (!t.toLowerCase().includes(criteria.text.toLowerCase())) continue;
            if (Array.from(el.children).some((c: any) => (c.innerText || c.textContent || "").includes(criteria.text))) continue;
          }
          if (criteria.attr) {
            const v = el.getAttribute(criteria.attr.name);
            if (v === null) continue;
            if (criteria.attr.value !== undefined && v !== criteria.attr.value) continue;
          }
          if (criteria.role && el.getAttribute("role") !== criteria.role) continue;
          const rect = el.getBoundingClientRect();
          out.push({
            tag: el.tagName.toLowerCase(),
            id: el.id || undefined,
            class: el.className?.toString?.() || undefined,
            text: (el.innerText || "").slice(0, 200),
            attrs: Object.fromEntries(Array.from(el.attributes).map((at: any) => [at.name, at.value])),
            bbox: { x: rect.x, y: rect.y, w: rect.width, h: rect.height },
          });
        }
        return out;
      }, { text: a.text, attr: a.attr, role: a.role, limit: a.limit });
      return ok(results);
    },
  },
  {
    name: "source_storage_dump",
    description: "Dump localStorage + sessionStorage + IndexedDB db names from the page.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const data = await s.page.evaluate(async () => {
        const local: Record<string, string> = {};
        const session: Record<string, string> = {};
        try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i)!; local[k] = localStorage.getItem(k) ?? ""; } } catch {}
        try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i)!; session[k] = sessionStorage.getItem(k) ?? ""; } } catch {}
        let idb: string[] = [];
        try {
          // @ts-ignore
          if (indexedDB.databases) idb = (await indexedDB.databases()).map((d: any) => d.name);
        } catch {}
        return { local, session, indexedDB: idb };
      });
      return ok(data);
    },
  },
  {
    name: "source_storage_set",
    description: "Set a key in localStorage or sessionStorage.",
    schema: z.object({
      area: z.enum(["local", "session"]),
      key: z.string(),
      value: z.string(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.page.evaluate(({ area, key, value }: any) => {
        const store = area === "local" ? localStorage : sessionStorage;
        store.setItem(key, value);
      }, { area: a.area, key: a.key, value: a.value });
      return ok("set");
    },
  },
];
