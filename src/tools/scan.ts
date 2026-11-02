import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

const SECURITY_HEADERS: Record<string, { desc: string; severity: "high" | "medium" | "low" }> = {
  "strict-transport-security": { desc: "forces HTTPS", severity: "high" },
  "content-security-policy": { desc: "mitigates XSS/clickjacking", severity: "high" },
  "x-frame-options": { desc: "clickjacking protection", severity: "medium" },
  "x-content-type-options": { desc: "stops MIME sniffing", severity: "medium" },
  "referrer-policy": { desc: "controls Referer leakage", severity: "low" },
  "permissions-policy": { desc: "feature isolation", severity: "low" },
  "cross-origin-opener-policy": { desc: "isolates browsing context", severity: "medium" },
  "cross-origin-resource-policy": { desc: "blocks cross-origin reads", severity: "medium" },
  "cross-origin-embedder-policy": { desc: "enables COOP+COEP isolation", severity: "low" },
};

async function doFetch(session: ReturnType<typeof hub.getSession>, url: string, opts: any = {}) {
  return session.context.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 0, ...opts });
}

export const scanTools: ToolDef[] = [
  {
    name: "scan_headers",
    description: "Audit response security headers for a URL.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const resp = await doFetch(s, a.url);
      const headers: Record<string, string> = {};
      for (const { name, value } of await resp.headersArray()) headers[name.toLowerCase()] = value;
      const findings: any[] = [];
      for (const [name, info] of Object.entries(SECURITY_HEADERS)) {
        if (!headers[name]) findings.push({ severity: info.severity, title: `Missing ${name}`, detail: info.desc });
      }
      if (headers["x-powered-by"]) findings.push({ severity: "low", title: "X-Powered-By leaks server tech", detail: headers["x-powered-by"] });
      if (headers["server"] && /\d/.test(headers["server"])) findings.push({ severity: "low", title: "Server header leaks version", detail: headers["server"] });
      const hsts = headers["strict-transport-security"];
      if (hsts && !/max-age=\d{7,}/.test(hsts)) findings.push({ severity: "medium", title: "HSTS max-age is short", detail: hsts });
      const csp = headers["content-security-policy"];
      if (csp) {
        if (/unsafe-inline/i.test(csp)) findings.push({ severity: "high", title: "CSP uses 'unsafe-inline'", detail: csp });
        if (/unsafe-eval/i.test(csp)) findings.push({ severity: "medium", title: "CSP uses 'unsafe-eval'", detail: csp });
        if (/\*(\s|;|$)/.test(csp)) findings.push({ severity: "medium", title: "CSP uses wildcard sources", detail: csp });
      }
      return ok({ url: a.url, status: resp.status(), headers, findings });
    },
  },
  {
    name: "scan_cookies",
    description: "Check cookie flags (HttpOnly, Secure, SameSite) for the current page.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const cookies = await s.context.cookies();
      const findings: any[] = [];
      for (const c of cookies) {
        if (!c.secure) findings.push({ severity: "medium", title: `Cookie '${c.name}' missing Secure flag` });
        if (!c.httpOnly) findings.push({ severity: "medium", title: `Cookie '${c.name}' missing HttpOnly flag` });
        if (!c.sameSite || c.sameSite === "None") findings.push({ severity: "low", title: `Cookie '${c.name}' SameSite=${c.sameSite ?? "unset"}` });
        if (c.name.toLowerCase().includes("session") && !c.httpOnly) findings.push({ severity: "high", title: `Session cookie '${c.name}' not HttpOnly` });
      }
      return ok({ cookies, findings });
    },
  },
  {
    name: "scan_cors",
    description: "Probe CORS behavior from a chosen Origin.",
    schema: z.object({ url: z.string().url(), origin: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const origin = a.origin ?? "https://evil.example";
      const resp = await doFetch(s, a.url, { headers: { Origin: origin } });
      const headers: Record<string, string> = {};
      for (const { name, value } of await resp.headersArray()) headers[name.toLowerCase()] = value;
      const acao = headers["access-control-allow-origin"];
      const acac = headers["access-control-allow-credentials"];
      const findings: any[] = [];
      if (acao === "*" && acac === "true") findings.push({ severity: "high", title: "ACAO=* with credentials=true (invalid but dangerous)" });
      if (acao === origin && acac === "true") findings.push({ severity: "high", title: "Reflects arbitrary Origin with credentials=true" });
      if (acao === "null") findings.push({ severity: "high", title: "ACAO=null — exploitable from sandboxed iframes" });
      if (acao === "*") findings.push({ severity: "low", title: "Public API (ACAO=*). Safe only if no auth state." });
      return ok({ sentOrigin: origin, acao, acac, headers, findings });
    },
  },
  {
    name: "scan_xss_reflected",
    description: "Reflected-XSS probe. Fuzzes a parameter with contextual payloads and flags unescaped reflections.",
    schema: z.object({
      url: z.string().url(),
      param: z.string(),
      method: z.enum(["GET", "POST"]).optional(),
      body: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const marker = `xZq${Math.random().toString(36).slice(2, 8)}`;
      const payloads = [
        `${marker}"><script>alert(1)</script>`,
        `${marker}'><svg/onload=alert(1)>`,
        `javascript:alert(${marker})`,
        `${marker}</title><img src=x onerror=alert(1)>`,
        `";alert(${marker});//`,
      ];
      const findings: any[] = [];
      for (const payload of payloads) {
        let url = a.url, body = a.body, headers: Record<string, string> = {};
        if ((a.method ?? "GET") === "GET") {
          const u = new URL(url); u.searchParams.set(a.param, payload); url = u.toString();
        } else {
          try { const o = JSON.parse(body ?? "{}"); o[a.param] = payload; body = JSON.stringify(o); headers["content-type"] = "application/json"; }
          catch { const p = new URLSearchParams(body ?? ""); p.set(a.param, payload); body = p.toString(); headers["content-type"] = "application/x-www-form-urlencoded"; }
        }
        const r = await doFetch(s, url, { method: a.method ?? "GET", data: body, headers });
        const text = await r.text().catch(() => "");
        const reflected = text.includes(payload);
        const scriptCtx = reflected && /<script[^>]*>[^<]*xZq/i.test(text);
        const attrCtx = reflected && /["'][^"']*xZq/.test(text);
        if (reflected) findings.push({
          severity: scriptCtx ? "high" : attrCtx ? "medium" : "low",
          payload, status: r.status(),
          reflectedIn: scriptCtx ? "script-context" : attrCtx ? "attribute-context" : "html-text",
          snippet: text.slice(Math.max(0, text.indexOf(marker) - 60), text.indexOf(marker) + payload.length + 60),
        });
      }
      return ok({ param: a.param, findings });
    },
  },
  {
    name: "scan_sqli",
    description: "Classic error-based + boolean-based SQLi probe. Compares baseline vs 'OR 1=1' responses and looks for SQL error strings.",
    schema: z.object({
      url: z.string().url(),
      param: z.string(),
      method: z.enum(["GET", "POST"]).optional(),
      body: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const payloads = ["'", "\"", "' OR '1'='1", "' AND '1'='2", "1 OR 1=1", "1 AND 1=2", "') OR ('1'='1", "; WAITFOR DELAY '0:0:3'--"];
      const sqlErrorPatterns = [
        /you have an error in your sql syntax/i,
        /warning: mysql/i,
        /mysqli?_fetch/i,
        /unclosed quotation mark/i,
        /pg_query\(\):/i,
        /sqlite\.exception/i,
        /ora-\d{5}/i,
        /quoted string not properly terminated/i,
        /microsoft odbc sql server driver/i,
      ];
      const baseline = await doFetch(s, a.url, { method: a.method ?? "GET", data: a.body });
      const baselineBody = await baseline.text().catch(() => "");
      const results: any[] = [];
      for (const payload of payloads) {
        let url = a.url, body = a.body, headers: Record<string, string> = {};
        if ((a.method ?? "GET") === "GET") {
          const u = new URL(url); u.searchParams.set(a.param, payload); url = u.toString();
        } else {
          try { const o = JSON.parse(body ?? "{}"); o[a.param] = payload; body = JSON.stringify(o); headers["content-type"] = "application/json"; }
          catch { const p = new URLSearchParams(body ?? ""); p.set(a.param, payload); body = p.toString(); headers["content-type"] = "application/x-www-form-urlencoded"; }
        }
        const t0 = Date.now();
        const r = await doFetch(s, url, { method: a.method ?? "GET", data: body, headers });
        const text = await r.text().catch(() => "");
        const dt = Date.now() - t0;
        const err = sqlErrorPatterns.find((p) => p.test(text));
        const diff = Math.abs(text.length - baselineBody.length);
        results.push({ payload, status: r.status(), length: text.length, lenDiff: diff, time: dt, sqlErrorMatch: err?.toString() ?? null });
      }
      const findings = results.filter((r) => r.sqlErrorMatch || r.time > 2800 || r.lenDiff > baselineBody.length * 0.2)
        .map((r) => ({ severity: r.sqlErrorMatch ? "high" : r.time > 2800 ? "medium" : "low", ...r }));
      return ok({ baselineLength: baselineBody.length, results, findings });
    },
  },
  {
    name: "scan_open_redirect",
    description: "Test a parameter for open-redirect by substituting an external target and watching for a 3xx Location.",
    schema: z.object({ url: z.string().url(), param: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const targets = ["https://evil.example/", "//evil.example", "/\\evil.example", "https://evil.example%2F@original", "/%2f/evil.example"];
      const findings: any[] = [];
      for (const t of targets) {
        const u = new URL(a.url); u.searchParams.set(a.param, t);
        const r = await doFetch(s, u.toString(), { maxRedirects: 0 });
        const loc = r.headers()["location"];
        if (r.status() >= 300 && r.status() < 400 && loc && /evil\.example/i.test(loc)) {
          findings.push({ severity: "high", payload: t, status: r.status(), location: loc });
        }
      }
      return ok({ param: a.param, findings });
    },
  },
  {
    name: "scan_mixed_content",
    description: "On an HTTPS page, find subresources loaded over HTTP.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const page = s.page.url();
      if (!page.startsWith("https://")) return ok({ findings: [], note: "page is not https" });
      const items = s.requests.filter((r) => r.url.startsWith("http://"));
      return ok({ findings: items.map((r) => ({ severity: "medium", url: r.url, resourceType: r.resourceType, status: r.status })) });
    },
  },
  {
    name: "scan_clickjacking",
    description: "Check if a page can be framed (missing X-Frame-Options / frame-ancestors).",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await doFetch(s, a.url);
      const h: Record<string, string> = {}; for (const { name, value } of await r.headersArray()) h[name.toLowerCase()] = value;
      const xfo = h["x-frame-options"];
      const csp = h["content-security-policy"] ?? "";
      const framesAnc = /frame-ancestors\s+[^;]+/i.test(csp);
      const framable = !xfo && !framesAnc;
      return ok({ framable, xFrameOptions: xfo ?? null, cspFrameAncestors: framesAnc, findings: framable ? [{ severity: "medium", title: "No framing protection — vulnerable to clickjacking" }] : [] });
    },
  },
  {
    name: "scan_jwt_decode",
    description: "Decode a JWT and flag common weaknesses: alg=none, HS256 with weak secret guesses, missing exp.",
    schema: z.object({ token: z.string() }),
    handler: async (a) => {
      const parts = a.token.split(".");
      if (parts.length !== 3) return err("not a JWT");
      const dec = (s: string) => JSON.parse(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
      let header, payload;
      try { header = dec(parts[0]); payload = dec(parts[1]); } catch (e: any) { return err(`decode failed: ${e.message}`); }
      const findings: any[] = [];
      if (String(header.alg).toLowerCase() === "none") findings.push({ severity: "high", title: "alg=none" });
      if (!payload.exp) findings.push({ severity: "medium", title: "no exp claim" });
      if (payload.exp && payload.exp * 1000 < Date.now()) findings.push({ severity: "low", title: "token expired" });
      if (!payload.iss) findings.push({ severity: "low", title: "no iss claim" });
      return ok({ header, payload, findings });
    },
  },
  {
    name: "scan_tech_fingerprint",
    description: "Fingerprint tech from headers, cookies, response body, and page globals.",
    schema: z.object({ url: z.string().url().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const url = a.url ?? s.page.url();
      const r = await doFetch(s, url);
      const headers: Record<string, string> = {}; for (const { name, value } of await r.headersArray()) headers[name.toLowerCase()] = value;
      const body = (await r.text().catch(() => "")).slice(0, 50000);
      const tech: Record<string, string> = {};
      const bodyMatch = (re: RegExp, label: string) => { const m = body.match(re); if (m) tech[label] = m[1] ?? "detected"; };
      if (headers["server"]) tech["server"] = headers["server"];
      if (headers["x-powered-by"]) tech["x-powered-by"] = headers["x-powered-by"];
      if (headers["x-aspnet-version"]) tech["asp.net"] = headers["x-aspnet-version"];
      if (headers["cf-ray"]) tech["cloudflare"] = "yes";
      if (headers["x-amz-cf-id"]) tech["aws-cloudfront"] = "yes";
      if (headers["x-vercel-id"]) tech["vercel"] = "yes";
      if (headers["x-github-request-id"]) tech["github-pages"] = "yes";
      bodyMatch(/wp-content|wp-includes/, "wordpress");
      bodyMatch(/Drupal\.settings|drupal\.org/, "drupal");
      bodyMatch(/__REACT_DEVTOOLS|_reactRootContainer/, "react");
      bodyMatch(/__VUE__|v-cloak/, "vue");
      bodyMatch(/ng-version="([^"]+)"/, "angular");
      bodyMatch(/__NEXT_DATA__/, "next.js");
      bodyMatch(/jquery[.-](\d+\.\d+\.\d+)/i, "jquery");
      try {
        const globals = await s.page.evaluate(() => Object.keys(window).filter(
          (k) => /React|Vue|Angular|jQuery|__NEXT|__NUXT|Shopify|Stripe|Intercom|Segment|GTag|dataLayer/.test(k),
        ));
        if (globals.length) tech["page_globals"] = globals.join(",");
      } catch { /* pumppet */ }
      return ok({ url, tech });
    },
  },
  {
    name: "scan_directory",
    description: "Probe a wordlist of common paths (admin, config, backups, .git/HEAD, .env). Returns anything that doesn't 404.",
    schema: z.object({
      baseUrl: z.string().url(),
      wordlist: z.array(z.string()).optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const words = a.wordlist ?? [
        ".env", ".git/HEAD", ".git/config", "admin", "admin/", "administrator/", "wp-admin/",
        "wp-login.php", "login", "backup.zip", "db.sql", "config.php", "config.json", "config.yaml",
        "phpinfo.php", "server-status", "actuator/health", ".DS_Store", "robots.txt", "sitemap.xml",
        "api/", "api/v1/", "swagger.json", "openapi.json", "graphql", "console/", "debug/",
      ];
      const base = a.baseUrl.replace(/\/$/, "");
      const results: any[] = [];
      let i = 0;
      const concurrency = 8;
      const worker = async () => {
        while (i < words.length) {
          const w = words[i++];
          const url = `${base}/${w}`;
          try {
            const r = await doFetch(s, url, { method: "GET" });
            if (r.status() !== 404) {
              const body = (await r.text().catch(() => "")).slice(0, 200);
              results.push({ url, status: r.status(), length: body.length, snippet: body });
            }
          } catch { /* pumppet */ }
        }
      };
      await Promise.all(Array.from({ length: concurrency }, () => worker()));
      return ok({ tried: words.length, found: results });
    },
  },
  {
    name: "scan_robots_sitemap",
    description: "Fetch /robots.txt and /sitemap.xml and extract URLs/paths.",
    schema: z.object({ baseUrl: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const base = a.baseUrl.replace(/\/$/, "");
      const out: any = {};
      try {
        const r = await doFetch(s, `${base}/robots.txt`);
        if (r.status() < 400) {
          const t = await r.text();
          out.robots = { body: t, disallows: Array.from(t.matchAll(/Disallow:\s*(.+)/gi)).map((m) => m[1].trim()) };
        }
      } catch { /* pumppet */ }
      try {
        const r = await doFetch(s, `${base}/sitemap.xml`);
        if (r.status() < 400) {
          const t = await r.text();
          out.sitemap = { urls: Array.from(t.matchAll(/<loc>([^<]+)<\/loc>/g)).map((m) => m[1]) };
        }
      } catch { /* pumppet */ }
      return ok(out);
    },
  },
  {
    name: "scan_forms",
    description: "List forms on the current page: action, method, inputs, CSRF-token heuristics.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const forms = await s.page.$$eval("form", (fs: any[]) => fs.map((f) => ({
        action: f.action, method: (f.method || "GET").toUpperCase(),
        id: f.id || null, name: f.name || null,
        inputs: Array.from(f.querySelectorAll("input,textarea,select")).map((i: any) => ({
          name: i.name, type: i.type || i.tagName.toLowerCase(), value: i.value?.slice?.(0, 100) ?? "",
        })),
      })));
      const findings: any[] = [];
      for (const f of forms) {
        if (f.method === "POST") {
          const hasCsrf = f.inputs.some((i: any) => /csrf|xsrf|token|authenticity/i.test(i.name));
          if (!hasCsrf) findings.push({ severity: "medium", title: `POST form has no visible CSRF token`, action: f.action });
        }
        for (const i of f.inputs) {
          if (i.type === "password" && !f.action.startsWith("https://")) findings.push({ severity: "high", title: `Password posted over non-HTTPS`, action: f.action });
        }
      }
      return ok({ forms, findings });
    },
  },
  {
    name: "scan_links",
    description: "Collect links from the current page (and optionally crawl a bit) scoped to the same origin.",
    schema: z.object({ depth: z.number().int().min(0).max(2).optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const start = s.page.url();
      const origin = new URL(start).origin;
      const seen = new Set<string>([start]);
      const q: string[] = [start];
      const external = new Set<string>();
      const maxDepth = a.depth ?? 0;
      let depth = 0;
      while (q.length && depth <= maxDepth) {
        const next: string[] = [];
        for (const u of q) {
          if (u !== start) {
            try { await s.page.goto(u, { waitUntil: "domcontentloaded", timeout: 10000 }); } catch { continue; }
          }
          const links = await s.page.$$eval("a[href]", (as: any[]) => as.map((a: any) => a.href));
          for (const l of links) {
            try {
              const abs = new URL(l, u).toString();
              if (abs.startsWith("javascript:") || abs.startsWith("mailto:")) continue;
              if (new URL(abs).origin === origin) {
                if (!seen.has(abs)) { seen.add(abs); next.push(abs); }
              } else external.add(abs);
            } catch { /* pumppet */ }
          }
        }
        q.length = 0; q.push(...next); depth++;
      }
      return ok({ internal: Array.from(seen), external: Array.from(external) });
    },
  },
  {
    name: "scan_subdomain_takeover",
    description: "Check a domain for common dangling-DNS takeover fingerprints (GitHub Pages, S3, Heroku, etc).",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const fingerprints: Array<{ host: RegExp; body: RegExp; svc: string }> = [
        { host: /github\.io/, body: /There isn't a GitHub Pages site here\.?/i, svc: "GitHub Pages" },
        { host: /s3[.-]/, body: /NoSuchBucket/i, svc: "AWS S3" },
        { host: /herokuapp\.com/, body: /No such app/i, svc: "Heroku" },
        { host: /azurewebsites\.net/, body: /404 Web Site not found/i, svc: "Azure" },
        { host: /\.fastly\.net/, body: /Fastly error: unknown domain/i, svc: "Fastly" },
        { host: /cloudfront\.net/, body: /Bad request\./i, svc: "CloudFront" },
      ];
      const r = await doFetch(s, a.url);
      const body = await r.text().catch(() => "");
      const findings: any[] = [];
      for (const f of fingerprints) {
        if (f.body.test(body)) findings.push({ severity: "high", service: f.svc, status: r.status(), snippet: body.slice(0, 200) });
      }
      return ok({ status: r.status(), findings });
    },
  },
  {
    name: "scan_full",
    description: "Run headers, cookies, forms, mixed-content, tech-fingerprint, clickjacking, robots+sitemap on the current page. One-shot.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const url = s.page.url();
      if (!url || url === "about:blank") return err("navigate the browser first");
      const results: Record<string, any> = {};
      const runs: Array<[string, () => Promise<any>]> = [
        ["headers", () => scanTools.find((t) => t.name === "scan_headers")!.handler({ url, sessionId: a.sessionId })],
        ["cookies", () => scanTools.find((t) => t.name === "scan_cookies")!.handler({ sessionId: a.sessionId })],
        ["forms", () => scanTools.find((t) => t.name === "scan_forms")!.handler({ sessionId: a.sessionId })],
        ["mixed_content", () => scanTools.find((t) => t.name === "scan_mixed_content")!.handler({ sessionId: a.sessionId })],
        ["tech", () => scanTools.find((t) => t.name === "scan_tech_fingerprint")!.handler({ sessionId: a.sessionId })],
        ["clickjacking", () => scanTools.find((t) => t.name === "scan_clickjacking")!.handler({ url, sessionId: a.sessionId })],
        ["robots_sitemap", () => scanTools.find((t) => t.name === "scan_robots_sitemap")!.handler({ baseUrl: new URL(url).origin, sessionId: a.sessionId })],
      ];
      for (const [k, fn] of runs) {
        try {
          const res = await fn();
          results[k] = JSON.parse(res.content[0].type === "text" ? res.content[0].text : "{}");
        } catch (e: any) { results[k] = { error: e?.message ?? String(e) }; }
      }
      const allFindings: any[] = [];
      for (const [cat, r] of Object.entries(results)) if (r?.findings) for (const f of r.findings) allFindings.push({ category: cat, ...f });
      return ok({ url, summary: { totalFindings: allFindings.length, high: allFindings.filter((f) => f.severity === "high").length, medium: allFindings.filter((f) => f.severity === "medium").length, low: allFindings.filter((f) => f.severity === "low").length }, findings: allFindings, raw: results });
    },
  },
];
