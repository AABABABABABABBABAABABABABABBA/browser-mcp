import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

const URL_LIKE_RE = /["'`(]\s*((?:https?:)?\/\/[^"'`()\s<>]{3,300}|\/[a-zA-Z0-9_\-./?=&%+:#]{1,300})\s*["'`)]/g;
const EMAIL_RE = /[\w.+-]+@[\w-]+\.[\w.-]{2,20}/g;
const COMMENT_HTML_RE = /<!--([\s\S]{3,500}?)-->/g;
const COMMENT_C_RE = /\/\*([\s\S]{3,500}?)\*\//g;
const PHP_HINTS = /<\?php|\.php\b|phpinfo|\$_(GET|POST|REQUEST|SERVER|SESSION|COOKIE)/g;
const PYTHON_HINTS = /\b(def\s+\w+\(|from\s+flask|django|wsgi|__name__\s*==\s*["']__main__)/g;
const RUBY_HINTS = /\b(require ['"]rails|def\s+\w+\s*\n|\.erb\b|<%=|ActiveRecord)/g;

export const discoverTools: ToolDef[] = [
  {
    name: "site_profile",
    description: "Deep profile of the current page. Pulls the HTML source first, finds every linked resource (scripts, styles, images, iframes, forms, links, data-*), fetches them, then grep-indexes everything plus the network capture for API endpoints, routes, emails, comments, secrets, tech markers (PHP/Python/Ruby/.NET/Node), and framework signatures. Works regardless of what the backend is written in.",
    schema: z.object({
      sameOriginOnly: z.boolean().optional(),
      fetchResources: z.boolean().optional().describe("default true — fetches every linked asset so later greps see them"),
      maxResources: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const sameOrigin = a.sameOriginOnly ?? true;
      const origin = (() => { try { return new URL(s.page.url()).origin; } catch { return null; } })();
      if (!origin) return err("navigate the browser first");
      const html = await s.page.content();

      // 1. Response headers of the main page
      let mainHeaders: Record<string, string> = {};
      try {
        const r = await s.context.request.fetch(s.page.url(), { ignoreHTTPSErrors: true, maxRedirects: 0 });
        for (const { name, value } of await r.headersArray()) mainHeaders[name.toLowerCase()] = value;
      } catch { /* pumppet */ }

      // 2. Parse the DOM for every resource and link
      const dom = await s.page.evaluate(() => {
        const abs = (u: string | null | undefined): string | null => { try { return u ? new URL(u, document.baseURI).toString() : null; } catch { return null; } };
        return {
          title: document.title,
          lang: document.documentElement.lang,
          meta: Array.from(document.querySelectorAll("meta")).map((m: any) => ({ name: m.name || m.getAttribute("property") || "", content: m.content || "" })).filter((x) => x.name),
          scripts: Array.from(document.querySelectorAll("script[src]")).map((e: any) => abs(e.src)).filter(Boolean),
          inlineScriptCount: document.querySelectorAll("script:not([src])").length,
          stylesheets: Array.from(document.querySelectorAll('link[rel~="stylesheet"]')).map((e: any) => abs(e.href)).filter(Boolean),
          images: Array.from(document.querySelectorAll("img[src]")).map((e: any) => abs(e.src)).filter(Boolean),
          iframes: Array.from(document.querySelectorAll("iframe[src]")).map((e: any) => abs(e.src)).filter(Boolean),
          links: Array.from(document.querySelectorAll("a[href]")).map((e: any) => abs(e.href)).filter(Boolean),
          preloads: Array.from(document.querySelectorAll('link[rel="preload"], link[rel="modulepreload"], link[rel="prefetch"]')).map((e: any) => abs(e.href)).filter(Boolean),
          forms: Array.from(document.querySelectorAll("form")).map((f: any) => ({
            action: f.action, method: (f.method || "GET").toUpperCase(),
            inputs: Array.from(f.querySelectorAll("input,textarea,select")).map((i: any) => ({ name: i.name, type: i.type || i.tagName.toLowerCase() })),
          })),
          dataAttrs: Array.from(document.querySelectorAll("[data-url], [data-api], [data-endpoint], [data-src]")).map((e: any) => ({ tag: e.tagName.toLowerCase(), attrs: Object.fromEntries(Array.from(e.attributes).filter((a: any) => a.name.startsWith("data-")).map((a: any) => [a.name, a.value])) })).slice(0, 40),
        };
      });

      // 3. Fetch every linked resource into the session cache (so grep sees it)
      const toFetch: string[] = [];
      const addIfSame = (u: string | null) => { if (!u) return; try { if (!sameOrigin || new URL(u).origin === origin) toFetch.push(u); } catch {} };
      for (const u of dom.scripts) addIfSame(u);
      for (const u of dom.stylesheets) addIfSame(u);
      for (const u of dom.iframes) addIfSame(u);
      for (const u of dom.preloads) addIfSame(u);
      for (const u of dom.images) addIfSame(u);
      const unique = Array.from(new Set(toFetch)).slice(0, a.maxResources ?? 80);
      const fetchedResources: Array<{ url: string; status: number; size: number; contentType: string }> = [];
      if (a.fetchResources !== false) {
        for (const u of unique) {
          try {
            const r = await s.context.request.fetch(u, { ignoreHTTPSErrors: true });
            const ct = r.headers()["content-type"] ?? "";
            const isBinary = /image\/|font\/|audio\/|video\/|octet-stream/.test(ct);
            const body = isBinary ? "" : (await r.text().catch(() => "")).slice(0, 300000);
            s.requests.push({
              id: Math.random().toString(36).slice(2, 10), ts: Date.now(),
              method: "GET", url: u, resourceType: isBinary ? "image" : "script",
              headers: {}, postData: null,
              status: r.status(),
              responseHeaders: { "content-type": ct },
              responseBodySnippet: body,
              fromCache: false, durationMs: null, failure: null,
            });
            fetchedResources.push({ url: u, status: r.status(), size: body.length, contentType: ct });
          } catch { /* pumppet */ }
        }
      }

      // 4. Index — walk every captured body (HTML, CSS, JS, JSON, text) plus main HTML
      const haystack: Array<{ url: string; body: string }> = [{ url: `page:${s.page.url()}`, body: html }];
      for (const r of s.requests) if (r.responseBodySnippet) haystack.push({ url: r.url, body: r.responseBodySnippet });

      const urls = new Set<string>();
      const emails = new Set<string>();
      const comments: Array<{ source: string; text: string }> = [];
      const techHits: Record<string, number> = {};
      for (const { url, body } of haystack) {
        URL_LIKE_RE.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = URL_LIKE_RE.exec(body))) {
          try {
            const abs: string = m[1].startsWith("http") ? m[1] : (m[1].startsWith("//") ? "https:" + m[1] : new URL(m[1], url.startsWith("page:") ? origin : url).toString());
            if (sameOrigin && new URL(abs).origin !== origin) continue;
            if (urls.size < 500) urls.add(abs);
          } catch {}
        }
        EMAIL_RE.lastIndex = 0;
        while ((m = EMAIL_RE.exec(body))) emails.add(m[0]);
        if (comments.length < 40) {
          for (const re of [COMMENT_HTML_RE, COMMENT_C_RE]) {
            re.lastIndex = 0;
            while ((m = re.exec(body)) && comments.length < 40) {
              const text = m[1].trim();
              if (text.length < 8) continue;
              if (/TODO|FIXME|XXX|HACK|password|secret|key|debug|internal|admin/i.test(text) || text.length > 50) comments.push({ source: url, text });
            }
          }
        }
        if (PHP_HINTS.test(body)) techHits.PHP = (techHits.PHP ?? 0) + 1;
        if (PYTHON_HINTS.test(body)) techHits.Python = (techHits.Python ?? 0) + 1;
        if (RUBY_HINTS.test(body)) techHits.Ruby = (techHits.Ruby ?? 0) + 1;
      }

      // 5. Backend tech hints from headers / cookies
      const serverTech: string[] = [];
      if (mainHeaders["x-powered-by"]) serverTech.push(mainHeaders["x-powered-by"]);
      if (mainHeaders["server"]) serverTech.push(mainHeaders["server"]);
      if (/phpsessid/i.test(mainHeaders["set-cookie"] ?? "")) serverTech.push("PHP (PHPSESSID cookie)");
      if (/jsessionid/i.test(mainHeaders["set-cookie"] ?? "")) serverTech.push("Java (JSESSIONID cookie)");
      if (/laravel_session|XSRF-TOKEN/i.test(mainHeaders["set-cookie"] ?? "")) serverTech.push("Laravel");
      if (/_rails_session|_csrf_token/i.test(mainHeaders["set-cookie"] ?? "")) serverTech.push("Ruby on Rails");
      if (mainHeaders["x-aspnet-version"]) serverTech.push(`ASP.NET ${mainHeaders["x-aspnet-version"]}`);
      if (mainHeaders["x-drupal-cache"]) serverTech.push("Drupal");
      if (/wp-content|wp-includes/.test(html)) serverTech.push("WordPress");
      if (/__NEXT_DATA__/.test(html)) serverTech.push("Next.js");
      if (/__NUXT__/.test(html)) serverTech.push("Nuxt");
      if (/ng-version/.test(html)) serverTech.push("Angular");

      return ok({
        url: s.page.url(),
        title: dom.title,
        lang: dom.lang,
        serverTech,
        responseHeaders: mainHeaders,
        bodyContentHints: techHits,
        resources: {
          scripts: dom.scripts.length,
          stylesheets: dom.stylesheets.length,
          images: dom.images.length,
          iframes: dom.iframes.length,
          preloads: dom.preloads.length,
          inlineScripts: dom.inlineScriptCount,
          forms: dom.forms.length,
          dataAttrs: dom.dataAttrs,
        },
        forms: dom.forms,
        meta: dom.meta,
        fetched: fetchedResources.length,
        extracted: {
          urls: Array.from(urls),
          emails: Array.from(emails),
          interestingComments: comments,
        },
      });
    },
  },
  {
    name: "crawl_site",
    description: "Breadth-first crawl this origin collecting every reachable page+body. Each page's response goes into the session capture so every other scanner can grep it. Works for any backend tech.",
    schema: z.object({
      maxPages: z.number().int().positive().optional(),
      depth: z.number().int().min(1).max(5).optional(),
      includePattern: z.string().optional().describe("regex: only crawl URLs matching this"),
      excludePattern: z.string().optional().describe("regex: skip URLs matching this (defaults to logout/image/binary paths)"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const start = s.page.url();
      const origin = new URL(start).origin;
      const maxPages = a.maxPages ?? 25;
      const maxDepth = a.depth ?? 2;
      const incRe = a.includePattern ? new RegExp(a.includePattern) : null;
      const excRe = new RegExp(a.excludePattern ?? "(logout|/signout|\\.(jpg|jpeg|png|gif|webp|svg|ico|pdf|zip|tar|gz|mp4|mp3|woff2?|ttf|otf))(\\?|$)", "i");

      const seen = new Set<string>([start]);
      const queue: Array<{ url: string; depth: number }> = [{ url: start, depth: 0 }];
      const visited: Array<{ url: string; status: number; size: number }> = [];

      while (queue.length && visited.length < maxPages) {
        const { url, depth } = queue.shift()!;
        try {
          const r = await s.context.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 3 });
          const ct = r.headers()["content-type"] ?? "";
          const text = (await r.text().catch(() => "")).slice(0, 300000);
          s.requests.push({
            id: Math.random().toString(36).slice(2, 10), ts: Date.now(),
            method: "GET", url, resourceType: "document",
            headers: {}, postData: null,
            status: r.status(),
            responseHeaders: Object.fromEntries((await r.headersArray()).map((h) => [h.name.toLowerCase(), h.value])),
            responseBodySnippet: text, fromCache: false, durationMs: null, failure: null,
          });
          visited.push({ url, status: r.status(), size: text.length });
          if (depth < maxDepth && /text\/html/.test(ct)) {
            const matches = Array.from(text.matchAll(/href\s*=\s*["']([^"']+)["']/gi));
            for (const m of matches) {
              try {
                const abs = new URL(m[1], url).toString();
                if (new URL(abs).origin !== origin) continue;
                if (incRe && !incRe.test(abs)) continue;
                if (excRe.test(abs)) continue;
                if (seen.has(abs)) continue;
                seen.add(abs);
                queue.push({ url: abs, depth: depth + 1 });
              } catch {}
            }
          }
        } catch (e: any) {
          visited.push({ url, status: 0, size: 0 });
        }
      }
      return ok({ crawled: visited.length, pages: visited, queued: queue.length });
    },
  },
  {
    name: "deep_scan",
    description: "One-shot: site_profile → crawl_site → scan_outdated → scan_js_secrets → scan_sensitive_files → scan_headers → api_from_source → routes_frontend_discover. Any tech stack.",
    schema: z.object({ crawlDepth: z.number().int().min(0).max(3).optional(), ...sessionArg }),
    handler: async (a) => {
      // Lazy-import siblings to avoid circular churn
      const { scanTools } = await import("./scan.js");
      const { vulnTools } = await import("./vuln.js");
      const { apiTools } = await import("./api.js");
      const s = hub.getSession(a.sessionId);
      if (!s.page.url() || s.page.url() === "about:blank") return err("navigate the browser first");

      const runs: Array<[string, () => Promise<any>]> = [
        ["profile", () => discoverTools.find((t) => t.name === "site_profile")!.handler({ sessionId: a.sessionId })],
      ];
      if ((a.crawlDepth ?? 1) > 0) runs.push(["crawl", () => discoverTools.find((t) => t.name === "crawl_site")!.handler({ depth: a.crawlDepth, sessionId: a.sessionId })]);
      runs.push(
        ["headers", () => scanTools.find((t) => t.name === "scan_headers")!.handler({ url: s.page.url(), sessionId: a.sessionId })],
        ["outdated", () => vulnTools.find((t) => t.name === "scan_outdated")!.handler({ sessionId: a.sessionId })],
        ["api_keys", () => vulnTools.find((t) => t.name === "scan_api_keys")!.handler({ sessionId: a.sessionId })],
        ["sensitive_files", () => vulnTools.find((t) => t.name === "scan_sensitive_files")!.handler({ baseUrl: new URL(s.page.url()).origin, sessionId: a.sessionId })],
        ["api_from_source", () => apiTools.find((t) => t.name === "api_from_source")!.handler({ sessionId: a.sessionId })],
        ["api_from_network", () => apiTools.find((t) => t.name === "api_from_network")!.handler({ sessionId: a.sessionId })],
        ["frontend_routes", () => apiTools.find((t) => t.name === "routes_frontend_discover")!.handler({ sessionId: a.sessionId })],
      );
      const out: Record<string, any> = {};
      const findings: any[] = [];
      for (const [k, fn] of runs) {
        try {
          const r = await fn();
          const parsed = JSON.parse(r.content[0].type === "text" ? r.content[0].text : "{}");
          out[k] = parsed;
          if (parsed?.findings) for (const f of parsed.findings) findings.push({ category: k, ...f });
        } catch (e: any) { out[k] = { error: e?.message ?? String(e) }; }
      }
      return ok({
        url: s.page.url(),
        summary: {
          totalFindings: findings.length,
          high: findings.filter((f) => f.severity === "high").length,
          medium: findings.filter((f) => f.severity === "medium").length,
          low: findings.filter((f) => f.severity === "low").length,
        },
        findings,
        results: out,
      });
    },
  },
];
