import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

// Script installed on every page to log every API-ish call that happens later
const HOOK_SCRIPT = `
(() => {
  if (window.__mcpHunt) return;
  const log = window.__mcpHunt = { fetch: [], xhr: [], ws: [], sse: [], beacon: [], postmessage: [], storage: [] };

  // fetch
  try {
    const orig = window.fetch;
    window.fetch = function(...args) {
      try {
        const req = args[0];
        const url = typeof req === "string" ? req : (req?.url ?? String(req));
        const method = args[1]?.method ?? (typeof req === "object" ? req?.method : null) ?? "GET";
        log.fetch.push({ ts: Date.now(), url, method, body: args[1]?.body ? String(args[1].body).slice(0, 2000) : null });
      } catch(e){}
      return orig.apply(this, args);
    };
  } catch(e){}

  // XMLHttpRequest
  try {
    const O = XMLHttpRequest.prototype.open;
    const S = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) { try { this.__m = method; this.__u = url; } catch(e){} return O.apply(this, [method, url, ...rest]); };
    XMLHttpRequest.prototype.send = function(body) { try { log.xhr.push({ ts: Date.now(), method: this.__m, url: this.__u, body: body ? String(body).slice(0, 2000) : null }); } catch(e){} return S.apply(this, arguments); };
  } catch(e){}

  // WebSocket
  try {
    const OW = window.WebSocket;
    window.WebSocket = function(url, protos) {
      const w = new OW(url, protos);
      try { log.ws.push({ ts: Date.now(), url: String(url), protos }); const _send = w.send; w.send = function(d) { try { log.ws.push({ ts: Date.now(), sent: String(d).slice(0, 2000), url: String(url) }); } catch(e){} return _send.apply(w, arguments); }; w.addEventListener("message", e => { try { log.ws.push({ ts: Date.now(), recv: String(e.data).slice(0, 2000), url: String(url) }); } catch(e){} }); } catch(e){}
      return w;
    };
    window.WebSocket.prototype = OW.prototype;
  } catch(e){}

  // EventSource / SSE
  try {
    const OE = window.EventSource;
    if (OE) {
      window.EventSource = function(url, cfg) { try { log.sse.push({ ts: Date.now(), url: String(url) }); } catch(e){} const e = new OE(url, cfg); e.addEventListener("message", ev => { try { log.sse.push({ ts: Date.now(), url: String(url), data: String(ev.data).slice(0, 2000) }); } catch(e){} }); return e; };
      window.EventSource.prototype = OE.prototype;
    }
  } catch(e){}

  // sendBeacon
  try {
    const OB = navigator.sendBeacon;
    if (OB) navigator.sendBeacon = function(url, data) { try { log.beacon.push({ ts: Date.now(), url: String(url), data: data ? String(data).slice(0, 2000) : null }); } catch(e){} return OB.apply(this, arguments); };
  } catch(e){}

  // postMessage receives (we don't intercept sends to avoid breaking stuff)
  try { window.addEventListener("message", (e) => { try { log.postmessage.push({ ts: Date.now(), origin: e.origin, data: typeof e.data === "string" ? e.data.slice(0, 2000) : JSON.stringify(e.data).slice(0, 2000) }); } catch(e){} }); } catch(e){}

  // localStorage + sessionStorage writes
  try {
    for (const store of [localStorage, sessionStorage]) {
      const name = store === localStorage ? "local" : "session";
      const _set = store.setItem;
      store.setItem = function(k, v) { try { log.storage.push({ ts: Date.now(), store: name, op: "set", key: k, value: String(v).slice(0, 2000) }); } catch(e){} return _set.apply(this, arguments); };
    }
  } catch(e){}
})();
`;

export const endpointHuntTools: ToolDef[] = [
  {
    name: "hunt_hooks_install",
    description: "Install page-level hooks on EVERY future page in the session — wraps fetch, XMLHttpRequest, WebSocket, EventSource (SSE), navigator.sendBeacon, incoming postMessages, and localStorage/sessionStorage writes. Call this BEFORE navigating; whatever the page does later is captured even if the HTTP capture already missed it (e.g. a service worker intercepts). Reload / re-navigate after calling.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.context.addInitScript({ content: HOOK_SCRIPT });
      return ok({ installed: true, note: "navigate or reload — hooks live on window.__mcpHunt" });
    },
  },
  {
    name: "hunt_hooks_dump",
    description: "Read everything the installed hooks captured on the current page — fetch calls, XHR opens, WebSocket URLs + frames, EventSource events, sendBeacon pings, received postMessages, storage writes.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const log = await s.page.evaluate(() => (window as any).__mcpHunt ?? null);
        if (!log) return ok({ note: "no hooks installed — call hunt_hooks_install first then reload" });
        return ok(log);
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "hunt_inline_data",
    description: "Extract every piece of data baked into the page — __NEXT_DATA__, __NUXT__, __APOLLO_STATE__, __PRELOADED_STATE__ / __INITIAL_STATE__, Angular TransferState, every <script type=\"application/json\"> and <script type=\"application/ld+json\">, plus any window.__.*= JSON literal at the end of a <script>. These are where SSR frameworks dump the actual API responses before any network call happens.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const data = await s.page.evaluate(() => {
          const out: Record<string, any> = {};
          const globals = ["__NEXT_DATA__", "__NUXT__", "__INITIAL_STATE__", "__PRELOADED_STATE__", "__APOLLO_STATE__", "__REDUX_STATE__", "__NG_TRANSFER_STATE__", "__GATSBY", "__REMIX_ROUTES__", "__data"];
          for (const g of globals) { try { if ((window as any)[g] !== undefined) out[g] = (window as any)[g]; } catch {} }
          // All json/ld+json script tags
          out["jsonScripts"] = Array.from(document.querySelectorAll("script[type='application/json'], script[type='application/ld+json']")).map((s: any) => { try { return { id: s.id || null, type: s.type, data: JSON.parse(s.textContent) }; } catch { return { id: s.id || null, type: s.type, raw: (s.textContent ?? "").slice(0, 500) }; } });
          // Grep inline scripts for window.X = {…}; patterns
          const inlineAssignments: any[] = [];
          for (const s of Array.from(document.querySelectorAll("script:not([src])"))) {
            const text = s.textContent ?? "";
            const matches = Array.from(text.matchAll(/window\.(\w+)\s*=\s*(\{[\s\S]*?\}|\[[\s\S]*?\])\s*;/g));
            for (const m of matches) { try { inlineAssignments.push({ name: m[1], data: JSON.parse(m[2]) }); } catch { inlineAssignments.push({ name: m[1], raw: m[2].slice(0, 500) }); } }
          }
          out["inlineAssignments"] = inlineAssignments;
          return out;
        });
        // Trim very large payloads to keep output readable
        const trim = (v: any, depth = 0): any => { if (depth > 8) return "[trimmed:deep]"; if (v == null) return v; if (typeof v === "string") return v.length > 400 ? v.slice(0, 400) + "..." : v; if (Array.isArray(v)) return v.slice(0, 30).map((x) => trim(x, depth + 1)); if (typeof v === "object") { const o: any = {}; for (const [k, val] of Object.entries(v).slice(0, 50)) o[k] = trim(val, depth + 1); return o; } return v; };
        return ok({ counts: { nextData: !!data.__NEXT_DATA__, nuxt: !!data.__NUXT__, apollo: !!data.__APOLLO_STATE__, redux: !!data.__PRELOADED_STATE__, jsonScripts: data.jsonScripts?.length ?? 0, inlineAssignments: data.inlineAssignments?.length ?? 0 }, data: trim(data) });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "hunt_dom_urls",
    description: "Walk every URL-shaped attribute in the DOM — href, src, action, formaction, data-url, data-src, data-api, data-endpoint, data-href, srcset, cite, poster, ping, background, longdesc. Finds endpoints baked into static HTML that never got fetched.",
    schema: z.object({ sameOriginOnly: z.boolean().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const origin = (() => { try { return new URL(s.page.url()).origin; } catch { return null; } })();
      const urls = await s.page.evaluate(() => {
        const attrs = ["href", "src", "action", "formaction", "data-url", "data-src", "data-api", "data-endpoint", "data-href", "data-image", "srcset", "cite", "poster", "ping", "background", "longdesc", "manifest", "data-background", "data-video"];
        const found: Array<{ tag: string; attr: string; value: string }> = [];
        const walk = (node: Element) => {
          for (const a of attrs) { const v = node.getAttribute(a); if (v && v.length > 1 && !/^(#|javascript:)/.test(v)) found.push({ tag: node.tagName.toLowerCase(), attr: a, value: v }); }
          for (const c of Array.from(node.children)) walk(c);
        };
        walk(document.documentElement);
        return found;
      });
      const resolved = urls.map((u) => { try { return { ...u, resolved: new URL(u.value, s.page.url()).toString() }; } catch { return u as any; } });
      let out = resolved;
      if (a.sameOriginOnly && origin) out = resolved.filter((u) => { try { return new URL(u.resolved ?? u.value).origin === origin; } catch { return false; } });
      // Dedup
      const seen = new Set<string>();
      out = out.filter((u: any) => { const k = u.resolved ?? u.value; if (seen.has(k)) return false; seen.add(k); return true; });
      return ok({ count: out.length, urls: out });
    },
  },
  {
    name: "hunt_bundle_endpoints",
    description: "Grep every captured JS body (chunks included — run chunks_discover first for max coverage) for URL/path patterns, GraphQL query names + operation IDs, and route tables that never fired. Finds hidden endpoints in bundles even when the UI never called them.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const urls = new Set<string>();
      const paths = new Set<string>();
      const graphqlOps = new Set<string>();
      const operationIds = new Set<string>();
      const routes = new Set<string>();
      const sources: Array<{ url: string; body: string }> = [];
      try { sources.push({ url: `page:${s.page.url()}`, body: await s.page.content() }); } catch { /* pumppet */ }
      for (const r of s.requests) if (r.responseBodySnippet) sources.push({ url: r.url, body: r.responseBodySnippet });

      for (const src of sources) {
        // absolute URLs
        for (const m of src.body.matchAll(/https?:\/\/[^\s"'`<>()]{3,200}/g)) urls.add(m[0]);
        // path literals: "/api/...", "/_next/data/...", "/graphql"
        for (const m of src.body.matchAll(/["'`](\/[a-zA-Z][\w\-\/.:$]{1,180})["'`]/g)) if (!/\.(png|jpg|gif|svg|css|woff2?|ttf)$/.test(m[1])) paths.add(m[1]);
        // GraphQL queries by operationName
        for (const m of src.body.matchAll(/(?:query|mutation|subscription)\s+(\w{2,40})\s*(?:\(|\{)/g)) graphqlOps.add(m[1]);
        // Apollo / Relay persisted query ids / hashes
        for (const m of src.body.matchAll(/["']?(?:documentId|operationId|queryId|persistedQueryId|sha256Hash)["']?\s*:\s*["']([a-f0-9]{32,})["']/g)) operationIds.add(m[1]);
        // React Router / Vue Router / Next route objects
        for (const m of src.body.matchAll(/path\s*:\s*["'`]([/][\w\-\/:*.]+)["'`]/g)) routes.add(m[1]);
      }
      return ok({
        urls: Array.from(urls).slice(0, 200),
        paths: Array.from(paths).slice(0, 300),
        graphqlOperations: Array.from(graphqlOps),
        persistedQueryIds: Array.from(operationIds).slice(0, 50),
        routes: Array.from(routes).slice(0, 100),
      });
    },
  },
  {
    name: "hunt_trigger_interactions",
    description: "Trigger latent requests — scroll to bottom, hover every button/link, click non-destructive buttons, wait between each. Captures what fires. Great for sites where data loads only on interaction.",
    schema: z.object({
      maxClicks: z.number().int().positive().optional().describe("default 20"),
      scrolls: z.number().int().positive().optional().describe("default 5"),
      skipSelectors: z.array(z.string()).optional().describe("CSS selectors to NOT click (defaults to logout/delete/submit)"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const before = s.requests.length;
      const skip = a.skipSelectors ?? ["[type=submit]", "button[type=submit]", "a[href*=logout]", "a[href*=signout]", "button:has-text(/delete|remove|logout|signout|sign out|log out/i)"];

      // Scroll
      for (let i = 0; i < (a.scrolls ?? 5); i++) {
        try { await s.page.evaluate(() => window.scrollBy(0, window.innerHeight)); await s.page.waitForTimeout(400); } catch { /* pumppet */ }
      }
      try { await s.page.evaluate(() => window.scrollTo(0, 0)); } catch {}

      // Hover visible buttons/links (may trigger lazy-load)
      try {
        const toHover = await s.page.$$("button:visible, a:visible, [role=button]:visible");
        for (let i = 0; i < Math.min(toHover.length, 15); i++) { try { await toHover[i].hover({ trial: false, timeout: 1000 }); await s.page.waitForTimeout(200); } catch {} }
      } catch {}

      // Click some non-destructive buttons
      let clicks = 0;
      try {
        const candidates = await s.page.$$('button:visible:not([type=submit]):not([disabled]), a[href]:visible:not([href*=logout]):not([href*=signout]):not([href^="#"])');
        for (const el of candidates) {
          if (clicks >= (a.maxClicks ?? 20)) break;
          try {
            const text = (await el.innerText().catch(() => "")).toLowerCase();
            if (/delete|remove|logout|sign out|log out|unsubscribe|cancel/i.test(text)) continue;
            await el.scrollIntoViewIfNeeded({ timeout: 500 });
            await el.click({ timeout: 1500, trial: false }); clicks++;
            await s.page.waitForTimeout(400);
          } catch { /* pumppet */ }
        }
      } catch { /* pumppet */ }

      const after = s.requests.length;
      const newReqs = s.requests.slice(before);
      return ok({
        clicked: clicks, scrolls: a.scrolls ?? 5,
        newRequestCount: after - before,
        endpoints: Array.from(new Set(newReqs.filter((r) => r.resourceType === "xhr" || r.resourceType === "fetch").map((r) => `${r.method} ${new URL(r.url).pathname}`))).slice(0, 50),
        allNewUrls: newReqs.map((r) => `${r.method} ${r.url} → ${r.status}`).slice(0, 100),
      });
    },
  },
  {
    name: "hunt_service_worker",
    description: "Detect + inspect registered service workers — scope, state, script URL, and what URLs they're caching (CacheStorage keys). Service workers can intercept requests and serve from cache without any network hitting your scanner.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const data = await s.page.evaluate(async () => {
          const out: any = { registrations: [], caches: {} };
          try {
            if ("serviceWorker" in navigator) {
              const regs = await navigator.serviceWorker.getRegistrations();
              out.registrations = regs.map((r) => ({ scope: r.scope, scriptURL: r.active?.scriptURL ?? r.installing?.scriptURL ?? r.waiting?.scriptURL, state: r.active?.state ?? "none" }));
            }
          } catch (e: any) { out.registrationsError = e.message; }
          try {
            if ("caches" in window) {
              const names = await caches.keys();
              for (const n of names) {
                const c = await caches.open(n);
                const reqs = await c.keys();
                out.caches[n] = reqs.map((r) => `${r.method} ${r.url}`).slice(0, 100);
              }
            }
          } catch (e: any) { out.cachesError = e.message; }
          return out;
        });
        return ok(data);
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "hunt_storage_data",
    description: "Dump localStorage + sessionStorage + IndexedDB object stores. Look for cached API responses, auth tokens, feature flags — often richer than the Network tab.",
    schema: z.object({ dbNames: z.array(z.string()).optional().describe("specific IDB db names; otherwise auto-detect"), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const data = await s.page.evaluate(async (dbNames: string[] | null) => {
          const out: any = { local: {}, session: {}, indexedDB: {} };
          try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i)!; out.local[k] = (localStorage.getItem(k) ?? "").slice(0, 2000); } } catch {}
          try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i)!; out.session[k] = (sessionStorage.getItem(k) ?? "").slice(0, 2000); } } catch {}
          try {
            let dbs = dbNames;
            if (!dbs && (indexedDB as any).databases) dbs = (await (indexedDB as any).databases()).map((d: any) => d.name).filter(Boolean);
            for (const name of (dbs ?? [])) {
              const dbInfo: any = { stores: {} };
              const open = indexedDB.open(name);
              const db: IDBDatabase = await new Promise((res, rej) => { open.onsuccess = () => res(open.result); open.onerror = () => rej(open.error); });
              for (const store of Array.from(db.objectStoreNames)) {
                try {
                  const tx = db.transaction(store, "readonly");
                  const os = tx.objectStore(store);
                  const cnt: number = await new Promise((res) => { const r = os.count(); r.onsuccess = () => res(r.result); r.onerror = () => res(-1); });
                  const items: any[] = [];
                  const req = os.getAll(null, 20);
                  await new Promise((res) => { req.onsuccess = () => { items.push(...req.result); res(null); }; req.onerror = () => res(null); });
                  dbInfo.stores[store] = { count: cnt, sampleItems: items.slice(0, 20).map((x) => JSON.stringify(x).slice(0, 1000)) };
                } catch (e: any) { dbInfo.stores[store] = { error: e.message }; }
              }
              out.indexedDB[name] = dbInfo;
              db.close();
            }
          } catch (e: any) { out.idbError = e.message; }
          return out;
        }, a.dbNames ?? null);
        return ok(data);
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "hunt_framework_endpoints",
    description: "Guess framework-specific data endpoints: Next.js /_next/data/<buildId>/<page>.json, Nuxt /_nuxt/data, WordPress /wp-json/wp/v2/*, Drupal JSON:API, Shopify /products.json, Rails *.json, GraphQL endpoints at common paths. Probes each and returns the ones that return JSON.",
    schema: z.object({ baseUrl: z.string().url().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const base = (a.baseUrl ?? s.page.url()).replace(/\/$/, "");
      const origin = new URL(base).origin;
      // Framework detection via inline data globals
      const detected = await s.page.evaluate(() => ({
        next: !!(window as any).__NEXT_DATA__ || !!document.querySelector("#__NEXT_DATA__"),
        nextBuildId: (window as any).__NEXT_DATA__?.buildId,
        nuxt: !!(window as any).__NUXT__,
        isWordPress: /wp-content|wp-includes/.test(document.documentElement.innerHTML.slice(0, 50000)),
        isDrupal: !!(window as any).Drupal || /sites\/default\/files/.test(document.documentElement.innerHTML.slice(0, 50000)),
        isShopify: /cdn\.shopify|Shopify/.test(document.documentElement.innerHTML.slice(0, 50000)),
      })).catch(() => ({ next: false, nuxt: false, isWordPress: false, isDrupal: false, isShopify: false, nextBuildId: null }));

      const toProbe: string[] = [];
      if (detected.next && detected.nextBuildId) {
        const path = new URL(base).pathname.replace(/^\/+/, "") || "index";
        toProbe.push(`${origin}/_next/data/${detected.nextBuildId}/${path}.json`);
        toProbe.push(`${origin}/_next/data/${detected.nextBuildId}/index.json`);
      }
      if (detected.nuxt) toProbe.push(`${origin}/_nuxt/data`, `${origin}/api`);
      if (detected.isWordPress) toProbe.push(`${origin}/wp-json`, `${origin}/wp-json/wp/v2/posts`, `${origin}/wp-json/wp/v2/users`, `${origin}/wp-json/wp/v2/pages`, `${origin}/wp-json/wp/v2/media`, `${origin}/?rest_route=/wp/v2/users`);
      if (detected.isDrupal) toProbe.push(`${origin}/jsonapi`, `${origin}/jsonapi/node/article`, `${origin}/jsonapi/user/user`);
      if (detected.isShopify) toProbe.push(`${origin}/products.json`, `${origin}/collections.json`, `${origin}/sitemap_products_1.xml`);
      // Universal
      toProbe.push(`${origin}/graphql`, `${origin}/api/graphql`, `${origin}/api`, `${origin}/api/v1`, `${origin}/api/v2`, `${origin}/openapi.json`, `${origin}/swagger.json`, `${origin}/api-docs`);
      // Rails: current URL + .json
      try { const u = new URL(base); if (u.pathname && u.pathname !== "/") toProbe.push(u.toString().replace(/\/?$/, "") + ".json"); } catch {}

      const hits: any[] = [];
      const uniq = Array.from(new Set(toProbe));
      for (const u of uniq) {
        try {
          const r = await s.context.request.fetch(u, { ignoreHTTPSErrors: true, maxRedirects: 2 });
          if (r.status() >= 400) continue;
          const ct = r.headers()["content-type"] ?? "";
          const text = (await r.text().catch(() => "")).slice(0, 2000);
          if (/json/i.test(ct) || /^\s*[\{\[]/.test(text)) hits.push({ url: u, status: r.status(), contentType: ct, size: text.length, preview: text.slice(0, 400) });
        } catch { /* pumppet */ }
      }
      return ok({ detected, probed: uniq.length, hits });
    },
  },
  {
    name: "hunt_everywhere",
    description: "One-shot: when the Network tab is empty, try EVERY data-discovery method — install hooks + reload + wait, dump inline SSR data, DOM URL walk, bundle grep, framework endpoint probe, interaction triggering, service worker + storage dump. Aggregated results.",
    schema: z.object({
      triggerInteractions: z.boolean().optional().describe("default true — click/scroll/hover to fire latent requests"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      if (!s.page.url() || s.page.url() === "about:blank") return err("navigate the browser first");
      const results: any = {};
      const run = async (label: string, name: string, args: any) => {
        try {
          const t = endpointHuntTools.find((x) => x.name === name)!;
          const r = await t.handler({ ...args, sessionId: a.sessionId });
          results[label] = JSON.parse((r.content[0] as any).text);
        } catch (e: any) { results[label] = { error: e.message }; }
      };

      await run("inlineData", "hunt_inline_data", {});
      await run("domUrls", "hunt_dom_urls", { sameOriginOnly: true });
      await run("bundleEndpoints", "hunt_bundle_endpoints", {});
      await run("frameworkEndpoints", "hunt_framework_endpoints", {});
      await run("serviceWorker", "hunt_service_worker", {});
      await run("storage", "hunt_storage_data", {});
      if (a.triggerInteractions !== false) await run("triggered", "hunt_trigger_interactions", { maxClicks: 15, scrolls: 5 });

      // Build the big unified endpoint list
      const allUrls = new Set<string>();
      for (const u of (results.domUrls?.urls ?? [])) allUrls.add(u.resolved ?? u.value);
      for (const u of (results.bundleEndpoints?.urls ?? [])) allUrls.add(u);
      for (const u of (results.bundleEndpoints?.paths ?? [])) allUrls.add(u);
      for (const u of (results.frameworkEndpoints?.hits ?? [])) allUrls.add(u.url);
      for (const u of (results.triggered?.endpoints ?? [])) allUrls.add(u);

      return ok({ url: s.page.url(), unifiedEndpointCount: allUrls.size, unifiedEndpoints: Array.from(allUrls).slice(0, 300), results });
    },
  },
];
