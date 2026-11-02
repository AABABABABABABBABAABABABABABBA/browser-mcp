import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

const CHUNK_URL_RE = /[\w\-./]+?\/[\w\-/]*?[a-f0-9]{6,20}[\w\-.]*\.(?:js|mjs|chunk\.js)(?=["'`?)\s]|$)/gi;
const SIMPLE_URL_RE = /["'`](\/[^"'`\s<>]{1,250})["'`]/g;
const FETCH_RE = /(?:fetch|axios\.(?:get|post|put|delete|patch|request)|\$\.(?:get|post|ajax)|request\.(?:get|post|put|delete))\s*\(\s*["'`]([^"'`]+)["'`]/g;
const URL_TEMPLATE_RE = /["'`]((?:https?:)?\/\/[^"'`\s<>]{1,200}|\/(?:api|v\d|graphql|rest|admin|internal)[^"'`\s<>]{0,200})["'`]/g;

async function fetchBody(session: ReturnType<typeof hub.getSession>, url: string, cap = 500000): Promise<string> {
  const r = await session.context.request.fetch(url, { ignoreHTTPSErrors: true });
  const t = await r.text().catch(() => "");
  return t.slice(0, cap);
}

export const apiTools: ToolDef[] = [
  {
    name: "chunks_discover",
    description: "Find and fetch every JS chunk/bundle this page relies on — webpack chunks, Next.js _buildManifest routes, Vite assets, dynamic imports, source-maps. Downloads them so later source_search / api_from_source can see what's really running.",
    schema: z.object({
      maxChunks: z.number().int().positive().optional(),
      includeSourceMaps: z.boolean().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const limit = a.maxChunks ?? 40;
      const chunks = new Set<string>();
      const origin = new URL(s.page.url()).origin;

      // 1) anything already in network capture that looks like JS
      for (const req of s.requests) {
        if (/\.m?js(\?|$)/i.test(req.url) || (req.responseHeaders?.["content-type"] ?? "").includes("javascript")) {
          chunks.add(req.url);
        }
      }
      // 2) <script src=> on the page
      try {
        const srcs = await s.page.$$eval("script[src]", (ss: any[]) => ss.map((s) => s.src));
        for (const u of srcs) chunks.add(u);
      } catch { /* pumppet */ }

      // 3) crawl the loaded JS for webpack chunk URLs + dynamic imports
      const seedBodies: Array<{ url: string; body: string }> = [];
      for (const url of Array.from(chunks).slice(0, limit)) {
        try { seedBodies.push({ url, body: await fetchBody(s, url) }); } catch { /* pumppet */ }
      }

      // 4) webpack: __webpack_require__.u + chunk id → url template, Next.js build manifest, Vite dyn imports
      const extraUrls = new Set<string>();
      for (const { url, body } of seedBodies) {
        // chunk filename hints
        const m1 = body.matchAll(CHUNK_URL_RE);
        for (const m of m1) extraUrls.add(new URL(m[0], url).toString());
        // Next.js _buildManifest reference
        const mBM = body.match(/\/_next\/static\/([^"'\s]+)\/_buildManifest\.js/);
        if (mBM) extraUrls.add(new URL(mBM[0], url).toString());
        // Vite rel="modulepreload"
        const mv = body.matchAll(/\/assets\/[\w\-]+-[a-f0-9]{6,20}\.(?:js|mjs)/g);
        for (const m of mv) extraUrls.add(new URL(m[0], url).toString());
      }

      // 5) rel=modulepreload links on the page
      try {
        const preloads = await s.page.$$eval('link[rel="modulepreload"], link[as="script"]', (ls: any[]) => ls.map((l) => l.href));
        for (const u of preloads) extraUrls.add(u);
      } catch { /* pumppet */ }

      // 6) Next.js build manifest explicitly
      try {
        const nextManifest = await s.page.evaluate(() => (window as any).__BUILD_MANIFEST ?? null);
        if (nextManifest && typeof nextManifest === "object") {
          for (const [, files] of Object.entries(nextManifest)) {
            if (!Array.isArray(files)) continue;
            for (const f of files as string[]) extraUrls.add(new URL(`/_next/${f}`, origin).toString());
          }
        }
      } catch { /* pumppet */ }

      // Fetch extras
      const results: Array<{ url: string; status: number; size: number; sourceMap?: string }> = [];
      let count = 0;
      for (const u of Array.from(new Set([...chunks, ...extraUrls]))) {
        if (count++ >= limit) break;
        try {
          const r = await s.context.request.fetch(u, { ignoreHTTPSErrors: true });
          const body = await r.text().catch(() => "");
          const entry: any = { url: u, status: r.status(), size: body.length };
          const smMatch = body.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
          if (smMatch) entry.sourceMap = new URL(smMatch[1], u).toString();
          // stash in network capture so source_search can grep it
          s.requests.push({
            id: Math.random().toString(36).slice(2, 10),
            ts: Date.now(),
            method: "GET", url: u, resourceType: "script",
            headers: {}, postData: null,
            status: r.status(),
            responseHeaders: Object.fromEntries((await r.headersArray()).map((h) => [h.name.toLowerCase(), h.value])),
            responseBodySnippet: body.slice(0, 200000),
            fromCache: false, durationMs: null, failure: null,
          });
          results.push(entry);
          if (a.includeSourceMaps && entry.sourceMap) {
            try {
              const smBody = await fetchBody(s, entry.sourceMap);
              const parsed = JSON.parse(smBody);
              entry.sourceMapSources = (parsed.sources ?? []).slice(0, 100);
            } catch { /* pumppet */ }
          }
        } catch { /* pumppet */ }
      }
      return ok({ fetched: results.length, chunks: results });
    },
  },
  {
    name: "api_from_network",
    description: "Group captured XHR/fetch requests by endpoint. Shows methods, status codes, response types, and sample payloads.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const groups = new Map<string, any>();
      for (const r of s.requests) {
        if (r.resourceType !== "xhr" && r.resourceType !== "fetch") {
          const ct = (r.responseHeaders?.["content-type"] ?? "").toLowerCase();
          if (!ct.includes("json") && !ct.includes("graphql")) continue;
        }
        const u = new URL(r.url);
        const key = `${u.origin}${u.pathname}`;
        const g = groups.get(key) ?? { endpoint: key, methods: new Set(), statusCodes: new Set(), contentTypes: new Set(), count: 0, samples: [] };
        g.methods.add(r.method);
        if (r.status) g.statusCodes.add(r.status);
        if (r.responseHeaders?.["content-type"]) g.contentTypes.add(r.responseHeaders["content-type"]);
        g.count++;
        if (g.samples.length < 2) g.samples.push({ url: r.url, method: r.method, status: r.status, bodySnippet: r.responseBodySnippet?.slice(0, 400) });
        groups.set(key, g);
      }
      const out = Array.from(groups.values()).map((g) => ({
        ...g, methods: Array.from(g.methods), statusCodes: Array.from(g.statusCodes), contentTypes: Array.from(g.contentTypes),
      }));
      return ok({ count: out.length, endpoints: out });
    },
  },
  {
    name: "api_from_source",
    description: "Grep every captured JS / HTML body for fetch/axios/XHR call sites and URL templates. Returns candidate endpoints with the surrounding code snippet.",
    schema: z.object({
      includeAbsolute: z.boolean().optional(),
      sameOriginOnly: z.boolean().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const sameOrigin = a.sameOriginOnly ?? true;
      const origin = (() => { try { return new URL(s.page.url()).origin; } catch { return null; } })();
      const seen = new Map<string, { url: string; via: string; where: string; snippet: string }>();

      const scan = (sourceUrl: string, body: string) => {
        const push = (url: string, via: string, idx: number) => {
          if (!url) return;
          try {
            const abs = url.startsWith("http") ? url : (url.startsWith("//") ? "https:" + url : new URL(url, sourceUrl).toString());
            if (sameOrigin && origin && new URL(abs).origin !== origin) return;
            if (!seen.has(abs)) {
              seen.set(abs, { url: abs, via, where: sourceUrl, snippet: body.slice(Math.max(0, idx - 40), idx + 120) });
            }
          } catch { /* pumppet */ }
        };
        let m: RegExpExecArray | null;
        FETCH_RE.lastIndex = 0;
        while ((m = FETCH_RE.exec(body))) push(m[1], "fetch/axios", m.index);
        URL_TEMPLATE_RE.lastIndex = 0;
        while ((m = URL_TEMPLATE_RE.exec(body))) push(m[1], "url-literal", m.index);
        if (a.includeAbsolute) {
          SIMPLE_URL_RE.lastIndex = 0;
          while ((m = SIMPLE_URL_RE.exec(body))) push(m[1], "path-literal", m.index);
        }
      };

      try { scan(`page:${s.page.url()}`, await s.page.content()); } catch { /* pumppet */ }
      for (const r of s.requests) if (r.responseBodySnippet) scan(r.url, r.responseBodySnippet);
      return ok({ count: seen.size, endpoints: Array.from(seen.values()) });
    },
  },
  {
    name: "api_graphql_introspect",
    description: "Send a GraphQL introspection query to a URL. Returns the schema types + root fields if introspection is on.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const query = `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields(includeDeprecated: true) { name description type { kind name ofType { kind name } } } } } }`;
      const r = await s.context.request.fetch(a.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        data: JSON.stringify({ query }),
        ignoreHTTPSErrors: true,
      });
      const text = await r.text().catch(() => "");
      try {
        const j = JSON.parse(text);
        if (j?.data?.__schema) {
          const schema = j.data.__schema;
          const findings = [{ severity: "high", title: "GraphQL introspection is enabled", detail: `${schema.types.length} types exposed` }];
          return ok({ status: r.status(), queryType: schema.queryType?.name, mutationType: schema.mutationType?.name, typeCount: schema.types.length, typeNames: schema.types.map((t: any) => t.name).slice(0, 100), rootQueries: (schema.types.find((t: any) => t.name === schema.queryType?.name)?.fields ?? []).map((f: any) => f.name), findings });
        }
        return ok({ status: r.status(), introspection: "disabled", body: text.slice(0, 1000) });
      } catch {
        return ok({ status: r.status(), body: text.slice(0, 1000) });
      }
    },
  },
  {
    name: "api_openapi_discover",
    description: "Probe common OpenAPI/Swagger locations and return the first spec it finds (title, version, paths).",
    schema: z.object({ baseUrl: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const base = a.baseUrl.replace(/\/$/, "");
      const paths = [
        "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
        "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs",
        "/api-docs", "/api/swagger.json", "/api/openapi.json",
        "/docs/swagger.json", "/.well-known/openapi",
        "/swagger-ui.html", "/swagger", "/docs", "/redoc",
      ];
      for (const p of paths) {
        try {
          const r = await s.context.request.fetch(base + p, { ignoreHTTPSErrors: true });
          if (r.status() >= 400) continue;
          const text = (await r.text()).slice(0, 500000);
          try {
            const j = JSON.parse(text);
            if (j.openapi || j.swagger || j.paths) {
              return ok({
                location: base + p, status: r.status(),
                spec: {
                  title: j.info?.title, version: j.info?.version,
                  openapi: j.openapi ?? j.swagger,
                  paths: Object.keys(j.paths ?? {}).slice(0, 200),
                  pathCount: Object.keys(j.paths ?? {}).length,
                },
              });
            }
          } catch {
            if (/swagger|openapi|redoc/i.test(text)) {
              return ok({ location: base + p, status: r.status(), hint: "swagger UI present, spec not JSON-parseable here", snippet: text.slice(0, 400) });
            }
          }
        } catch { /* pumppet */ }
      }
      return ok({ location: null, note: "no public spec found" });
    },
  },
  {
    name: "routes_frontend_discover",
    description: "Extract frontend routes from every captured JS bundle — React Router, Next.js _buildManifest, Vue Router, SvelteKit, Angular, SolidJS.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const routes = new Set<string>();
      const sources = new Map<string, string>();

      // Next.js build manifest in page globals (direct, if available)
      try {
        const bm = await s.page.evaluate(() => (window as any).__BUILD_MANIFEST ?? null);
        if (bm && typeof bm === "object") for (const key of Object.keys(bm)) if (key.startsWith("/")) { routes.add(key); sources.set(key, "next:__BUILD_MANIFEST"); }
      } catch { /* pumppet */ }

      // Grep every captured body
      const push = (route: string, where: string) => {
        if (!route.startsWith("/") || route.length > 200) return;
        if (/[<>\n]/.test(route)) return;
        if (!routes.has(route)) { routes.add(route); sources.set(route, where); }
      };
      const PATTERNS: Array<{ re: RegExp; via: string; group?: number }> = [
        { re: /path\s*:\s*["'`]([/][^"'`]{0,150})["'`]/g, via: "path-prop" },
        { re: /<\s*Route[^>]*\bpath\s*=\s*["'`]([^"'`]+)["'`]/g, via: "<Route path=>" },
        { re: /createBrowserRouter\s*\(\s*\[([\s\S]{0,8000}?)\]/g, via: "createBrowserRouter" },
        { re: /pathname\s*:\s*["'`]([/][^"'`]{0,150})["'`]/g, via: "pathname" },
        { re: /["'`](\/[a-zA-Z0-9][\w\-/:]*?)["'`]\s*:\s*{\s*(?:component|page|loader)/g, via: "route-config" },
      ];
      for (const r of s.requests) {
        const b = r.responseBodySnippet; if (!b) continue;
        for (const p of PATTERNS) {
          p.re.lastIndex = 0; let m: RegExpExecArray | null;
          while ((m = p.re.exec(b))) {
            if (p.via === "createBrowserRouter") {
              const inner = m[1];
              const inner2 = inner.matchAll(/path\s*:\s*["'`]([/][^"'`]{0,150})["'`]/g);
              for (const i of inner2) push(i[1], `${r.url}:createBrowserRouter`);
            } else {
              push(m[1], `${r.url}:${p.via}`);
            }
          }
        }
      }
      return ok({ count: routes.size, routes: Array.from(routes).sort().map((r) => ({ path: r, via: sources.get(r) })) });
    },
  },
  {
    name: "routes_backend_probe",
    description: "Probe a list of candidate paths (or an auto-list from captured sources) against the base URL. Returns status / size for each. Flags routes that respond unauthenticated.",
    schema: z.object({
      baseUrl: z.string().url(),
      paths: z.array(z.string()).optional().describe("defaults to a merged list from robots.txt, api_from_source, routes_frontend_discover, and a common-paths wordlist"),
      concurrency: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const base = a.baseUrl.replace(/\/$/, "");
      const origin = new URL(base).origin;
      let paths = a.paths?.slice();
      if (!paths) {
        const common = ["/api", "/api/v1", "/api/v2", "/graphql", "/admin", "/admin/login", "/dashboard", "/user", "/users", "/profile", "/settings", "/debug", "/healthz", "/health", "/status", "/metrics", "/actuator/env", "/actuator/health", "/console", "/.env", "/_next/static", "/wp-json/wp/v2/users", "/wp-admin"];
        const extracted = new Set<string>();
        for (const r of s.requests) if (r.url.startsWith(origin)) extracted.add(new URL(r.url).pathname);
        paths = Array.from(new Set([...common, ...extracted])).slice(0, 120);
      }
      const concurrency = Math.min(a.concurrency ?? 8, 15);
      const results: any[] = []; let i = 0;
      const worker = async () => {
        while (i < paths!.length) {
          const p = paths![i++];
          const url = base + (p.startsWith("/") ? p : "/" + p);
          try {
            const r = await s.context.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 0 });
            const text = (await r.text().catch(() => "")).slice(0, 2000);
            const sensitiveMarkers = [/logged in as/i, /logout/i, /admin panel/i, /dashboard/i, /"email"\s*:/, /password/i, /private[-_]key/i];
            const hits = sensitiveMarkers.filter((re) => re.test(text)).map((re) => re.source);
            results.push({ path: p, url, status: r.status(), size: text.length, authHints: hits, redirectLocation: r.headers()["location"] ?? null });
          } catch (e: any) { results.push({ path: p, url, error: e?.message ?? String(e) }); }
        }
      };
      await Promise.all(Array.from({ length: concurrency }, () => worker()));
      const findings = results.filter((r) => r.status === 200 && r.authHints?.length)
        .map((r) => ({ severity: "high", title: `Possibly unauthenticated access`, path: r.path, hints: r.authHints }));
      return ok({ tried: results.length, results, findings });
    },
  },
  {
    name: "routes_test_auth",
    description: "For each route, make two requests — one WITH the session's cookies, one WITHOUT. Compare. Routes whose unauth response matches the auth response are candidate IDOR/auth-bypass bugs.",
    schema: z.object({
      baseUrl: z.string().url(),
      paths: z.array(z.string()).min(1),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const base = a.baseUrl.replace(/\/$/, "");
      const authed = s.context.request;
      const anonCtx = await s.context.browser()!.newContext({ ignoreHTTPSErrors: true });
      const results: any[] = [];
      try {
        for (const p of a.paths) {
          const url = base + (p.startsWith("/") ? p : "/" + p);
          try {
            const [ra, rb] = await Promise.all([
              authed.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 0 }),
              anonCtx.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 0 }),
            ]);
            const [ta, tb] = await Promise.all([ra.text().catch(() => ""), rb.text().catch(() => "")]);
            const same = ta.length > 50 && Math.abs(ta.length - tb.length) < ta.length * 0.05;
            results.push({
              path: p,
              authed: { status: ra.status(), size: ta.length },
              anon: { status: rb.status(), size: tb.length },
              bodiesLookEqual: same,
              finding: same && ra.status() === 200 && rb.status() === 200 ? { severity: "high", title: "Route returns identical content without authentication" } : null,
            });
          } catch (e: any) { results.push({ path: p, error: e?.message ?? String(e) }); }
        }
      } finally { await anonCtx.close(); }
      return ok({ results, findings: results.filter((r) => r.finding).map((r) => ({ path: r.path, ...r.finding })) });
    },
  },
];
