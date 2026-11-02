import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

async function fetchWith(session: ReturnType<typeof hub.getSession>, url: string, opts: any = {}) {
  return session.context.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 0, ...opts });
}

const SSTI_PROBES: Array<{ engine: string; payload: string; expect: string }> = [
  { engine: "Jinja2 / Twig", payload: "{{7*7}}", expect: "49" },
  { engine: "Jinja2 (concat)", payload: "{{'7'*7}}", expect: "7777777" },
  { engine: "Mako", payload: "${7*7}", expect: "49" },
  { engine: "Handlebars / ERB", payload: "<%= 7*7 %>", expect: "49" },
  { engine: "Smarty", payload: "{7*7}", expect: "49" },
  { engine: "FreeMarker", payload: "${7*7}", expect: "49" },
  { engine: "Velocity", payload: "#set($x=7*7)$x", expect: "49" },
  { engine: "Spring EL", payload: "#{7*7}", expect: "49" },
];

const LFI_PROBES = [
  "../../../../etc/passwd",
  "..%2f..%2f..%2f..%2fetc%2fpasswd",
  "....//....//....//etc/passwd",
  "/etc/passwd",
  "C:\\Windows\\win.ini",
  "..\\..\\..\\..\\Windows\\win.ini",
  "php://filter/convert.base64-encode/resource=index.php",
  "/proc/self/environ",
  "file:///etc/passwd",
];

const CMDI_PROBES = [
  { payload: "; sleep 5", mode: "time" as const, delayMs: 4500 },
  { payload: "| sleep 5", mode: "time" as const, delayMs: 4500 },
  { payload: "`sleep 5`", mode: "time" as const, delayMs: 4500 },
  { payload: "$(sleep 5)", mode: "time" as const, delayMs: 4500 },
  { payload: "& ping -n 5 127.0.0.1 &", mode: "time" as const, delayMs: 4000 },
];

async function substitute(url: string, body: string | undefined, loc: string, name: string, value: string, headers: Record<string, string>): Promise<{ url: string; body?: string; headers: Record<string, string> }> {
  let u = url;
  let b = body;
  const h = { ...headers };
  if (loc === "query") { const parsed = new URL(u); parsed.searchParams.set(name, value); u = parsed.toString(); }
  else if (loc === "path") { u = u.replace(`{${name}}`, encodeURIComponent(value)); }
  else if (loc === "header") { h[name] = value; }
  else if (loc === "body-form") {
    const p = new URLSearchParams(String(b ?? "")); p.set(name, value); b = p.toString();
    h["content-type"] = h["content-type"] ?? "application/x-www-form-urlencoded";
  } else if (loc === "body-json") {
    try { const o = JSON.parse(b ?? "{}"); o[name] = value; b = JSON.stringify(o); } catch { b = JSON.stringify({ [name]: value }); }
    h["content-type"] = h["content-type"] ?? "application/json";
  }
  return { url: u, body: b, headers: h };
}

export const vuln2Tools: ToolDef[] = [
  {
    name: "scan_ssti",
    description: "Server-Side Template Injection probe. Fires engine-specific math payloads ({{7*7}}, ${7*7}, <%= 7*7 %>, ...) against a parameter and watches for the computed value in the response.",
    schema: z.object({
      url: z.string().url(), param: z.string(),
      paramLocation: z.enum(["query", "body-form", "body-json", "header", "path"]).optional(),
      method: z.enum(["GET", "POST", "PUT"]).optional(),
      body: z.string().optional(),
      headers: z.record(z.string()).optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const findings: any[] = [];
      const loc = a.paramLocation ?? (a.body ? "body-form" : "query");
      const method = a.method ?? (a.body ? "POST" : "GET");
      for (const probe of SSTI_PROBES) {
        const sub = await substitute(a.url, a.body, loc, a.param, probe.payload, a.headers ?? {});
        try {
          const r = await fetchWith(s, sub.url, { method, data: sub.body, headers: sub.headers });
          const text = (await r.text().catch(() => "")).slice(0, 20000);
          if (text.includes(probe.expect) && !text.includes(probe.payload)) {
            findings.push({ severity: "high", engine: probe.engine, payload: probe.payload, found: probe.expect, status: r.status(), snippet: text.slice(Math.max(0, text.indexOf(probe.expect) - 60), text.indexOf(probe.expect) + 60) });
          }
        } catch { /* pumppet */ }
      }
      return ok({ param: a.param, findings });
    },
  },
  {
    name: "scan_lfi",
    description: "Local File Inclusion / path traversal probe. Submits ../../etc/passwd and friends, checks for 'root:x:' or Windows [extensions] markers.",
    schema: z.object({
      url: z.string().url(), param: z.string(),
      paramLocation: z.enum(["query", "body-form", "body-json", "header", "path"]).optional(),
      method: z.enum(["GET", "POST"]).optional(),
      body: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const loc = a.paramLocation ?? "query";
      const method = a.method ?? "GET";
      const findings: any[] = [];
      for (const payload of LFI_PROBES) {
        const sub = await substitute(a.url, a.body, loc, a.param, payload, {});
        try {
          const r = await fetchWith(s, sub.url, { method, data: sub.body, headers: sub.headers });
          const text = (await r.text().catch(() => "")).slice(0, 50000);
          const unixHit = /root:x:0:0/i.test(text) || /daemon:x:/.test(text);
          const winHit = /\[extensions\]|; for 16-bit app support/i.test(text);
          const phpB64 = /^[A-Za-z0-9+/]{200,}={0,2}$/.test(text.trim()) && payload.includes("php://filter");
          if (unixHit || winHit || phpB64) {
            findings.push({ severity: "high", payload, hit: unixHit ? "unix-passwd" : winHit ? "windows-win.ini" : "php-filter-b64", status: r.status(), snippet: text.slice(0, 300) });
          }
        } catch { /* pumppet */ }
      }
      return ok({ param: a.param, findings });
    },
  },
  {
    name: "scan_cmdi_time",
    description: "Time-based command injection probe. Fires `; sleep 5` and shell equivalents and measures response delta. Flags any payload where response time ≥ ~5s.",
    schema: z.object({
      url: z.string().url(), param: z.string(),
      paramLocation: z.enum(["query", "body-form", "body-json", "header"]).optional(),
      method: z.enum(["GET", "POST"]).optional(),
      body: z.string().optional(),
      baselineMs: z.number().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const loc = a.paramLocation ?? "query";
      const method = a.method ?? "GET";
      let baseline = a.baselineMs;
      if (!baseline) {
        const sub = await substitute(a.url, a.body, loc, a.param, "baseline", {});
        const t0 = Date.now();
        try { await fetchWith(s, sub.url, { method, data: sub.body, headers: sub.headers }); } catch { /* pumppet */ }
        baseline = Date.now() - t0;
      }
      const findings: any[] = [];
      for (const probe of CMDI_PROBES) {
        const sub = await substitute(a.url, a.body, loc, a.param, probe.payload, {});
        const t0 = Date.now();
        try {
          await fetchWith(s, sub.url, { method, data: sub.body, headers: sub.headers, timeout: 20000 } as any);
        } catch { /* pumppet */ }
        const dt = Date.now() - t0;
        if (dt >= probe.delayMs && dt - baseline! >= 4000) {
          findings.push({ severity: "high", payload: probe.payload, timeMs: dt, baselineMs: baseline });
        }
      }
      return ok({ param: a.param, baselineMs: baseline, findings });
    },
  },
  {
    name: "scan_crlf",
    description: "CRLF injection probe. Submits payloads that inject a Set-Cookie or X-Injected header and checks whether the server echoes them.",
    schema: z.object({ url: z.string().url(), param: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const marker = "mcpInjected" + Math.random().toString(36).slice(2, 6);
      const payloads = [`foo%0D%0ASet-Cookie:%20${marker}=1`, `foo%0d%0aX-Injected:%20${marker}`, `foo\r\nX-Injected: ${marker}`, `foo%E5%98%8A%E5%98%8DX-Injected: ${marker}`];
      const findings: any[] = [];
      for (const p of payloads) {
        const u = new URL(a.url); u.searchParams.set(a.param, p); // keep encoded
        try {
          const r = await fetchWith(s, u.toString(), { method: "GET" });
          const h = r.headers();
          for (const k of Object.keys(h)) if (h[k].includes(marker) || k.includes(marker.toLowerCase())) {
            findings.push({ severity: "high", payload: p, injected: `${k}: ${h[k]}` });
          }
        } catch { /* pumppet */ }
      }
      return ok({ param: a.param, findings });
    },
  },
  {
    name: "scan_host_header",
    description: "Host-header injection probe. Overrides Host / X-Forwarded-Host / Forwarded headers with an attacker-controlled value and watches for reflection in Location, body links, or self-referencing URLs.",
    schema: z.object({ url: z.string().url(), evilHost: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const evil = a.evilHost ?? "evil.attacker.example";
      const headerSets = [
        { Host: evil },
        { "X-Forwarded-Host": evil },
        { "X-Forwarded-Server": evil },
        { Forwarded: `host=${evil}` },
        { "X-Host": evil },
        { "X-Original-Host": evil },
      ];
      const findings: any[] = [];
      for (const h of headerSets) {
        try {
          const r = await fetchWith(s, a.url, { method: "GET", headers: h });
          const body = (await r.text().catch(() => "")).slice(0, 20000);
          const loc = r.headers()["location"] ?? "";
          if (loc.includes(evil) || body.includes(evil)) {
            findings.push({ severity: "high", via: Object.keys(h)[0], where: loc.includes(evil) ? "Location header" : "body", status: r.status(), loc });
          }
        } catch { /* pumppet */ }
      }
      return ok({ evilHost: evil, findings });
    },
  },
  {
    name: "scan_prototype_pollution",
    description: "Client-side prototype pollution probe. Visits the current URL with ?__proto__[polluted]=yes and friends, then checks whether Object.prototype.polluted leaked onto the page.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const base = s.page.url();
      const marker = "pp" + Math.random().toString(36).slice(2, 6);
      const payloads = [
        `?__proto__[${marker}]=yes`,
        `?__proto__.${marker}=yes`,
        `?constructor[prototype][${marker}]=yes`,
        `?constructor.prototype.${marker}=yes`,
      ];
      const findings: any[] = [];
      for (const p of payloads) {
        try {
          const url = base.includes("?") ? base + "&" + p.slice(1) : base + p;
          await s.page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
          const poll = await s.page.evaluate((m) => ({ onProto: (Object.prototype as any)[m], onObj: ({} as any)[m] }), marker);
          if (poll.onProto === "yes" || poll.onObj === "yes") findings.push({ severity: "high", payload: p, pollutedKey: marker });
        } catch { /* pumppet */ }
      }
      return ok({ findings });
    },
  },
  {
    name: "scan_nosql_injection",
    description: "MongoDB NoSQL injection probe. Replaces a parameter with operator payloads ({$ne:null}, {$gt:''}, etc.) via JSON body or `[$ne]=` query, flags responses that look authenticated or expanded.",
    schema: z.object({
      url: z.string().url(), param: z.string(), method: z.enum(["GET", "POST"]).optional(),
      bodyIsJson: z.boolean().optional(),
      body: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const method = a.method ?? "POST";
      const findings: any[] = [];
      const operators = [{ $ne: null }, { $gt: "" }, { $regex: ".*" }, { $exists: true }];
      // baseline
      let base: any;
      try {
        const sub = await substitute(a.url, a.body, a.bodyIsJson ? "body-json" : "body-form", a.param, "baseline_" + Math.random().toString(36).slice(2, 6), {});
        const r = await fetchWith(s, sub.url, { method, data: sub.body, headers: sub.headers });
        base = { status: r.status(), size: (await r.text().catch(() => "")).length };
      } catch { base = { status: 0, size: 0 }; }
      for (const op of operators) {
        try {
          let data: string, headers: Record<string, string> = {};
          if (a.bodyIsJson) {
            const o = JSON.parse(a.body ?? "{}"); o[a.param] = op; data = JSON.stringify(o);
            headers["content-type"] = "application/json";
          } else {
            const p = new URLSearchParams(a.body ?? "");
            for (const [k, v] of Object.entries(op)) p.set(`${a.param}[${k}]`, String(v));
            data = p.toString();
            headers["content-type"] = "application/x-www-form-urlencoded";
          }
          const r = await fetchWith(s, a.url, { method, data, headers });
          const text = await r.text().catch(() => "");
          const diff = text.length - base.size;
          const authed = /logout|dashboard|welcome|token/i.test(text) && !/invalid|incorrect/i.test(text);
          if (r.status() !== base.status || Math.abs(diff) > Math.max(100, base.size * 0.3) || authed) {
            findings.push({ severity: authed ? "high" : "medium", operator: op, status: r.status(), size: text.length, baselineSize: base.size, snippet: text.slice(0, 300) });
          }
        } catch { /* pumppet */ }
      }
      return ok({ param: a.param, baseline: base, findings });
    },
  },
  {
    name: "scan_dom_xss",
    description: "DOM XSS probe. Loads the page with a canary in location.hash / search and checks whether the canary ends up unescaped in the DOM (innerHTML, dangerouslySetInnerHTML, eval sinks).",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const base = s.page.url();
      const canary = "domXss" + Math.random().toString(36).slice(2, 8);
      const marker = `<img src=x onerror='window.__dx=\"${canary}\"'>`;
      const encoded = encodeURIComponent(marker);
      const places = [`#${encoded}`, `?dx=${encoded}`, `?q=${encoded}&name=${encoded}`];
      const findings: any[] = [];
      for (const p of places) {
        try {
          await s.page.goto(base.split("#")[0].split("?")[0] + p, { waitUntil: "domcontentloaded", timeout: 15000 });
          await s.page.waitForTimeout(500);
          const html = await s.page.content();
          const executed = await s.page.evaluate((c) => (window as any).__dx === c, canary);
          if (executed) findings.push({ severity: "high", vector: p, how: "javascript executed via DOM sink" });
          else if (html.includes("onerror=") && html.includes(canary)) findings.push({ severity: "medium", vector: p, how: "payload reflected unencoded in DOM" });
        } catch { /* pumppet */ }
      }
      return ok({ findings });
    },
  },
  {
    name: "scan_ssrf",
    description: "SSRF probe. Submits common SSRF canaries (localhost, 127.0.0.1, 169.254.169.254, file://) into a parameter and compares status / body / timing against a baseline. External OOB probing requires your own canary host via `oobHost`.",
    schema: z.object({
      url: z.string().url(), param: z.string(),
      paramLocation: z.enum(["query", "body-form", "body-json", "header"]).optional(),
      method: z.enum(["GET", "POST"]).optional(),
      oobHost: z.string().optional().describe("your out-of-band canary (e.g. interact.sh) — hit by server if SSRF succeeds"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const loc = a.paramLocation ?? "query";
      const method = a.method ?? "GET";
      const probes = [
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:22",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_PING",
        "dict://127.0.0.1:11211/",
      ];
      if (a.oobHost) probes.push(`http://${a.oobHost}/mcp-ssrf-${Math.random().toString(36).slice(2, 8)}`);
      // baseline
      let base: any = { size: 0, status: 0, time: 0 };
      try {
        const sub = await substitute(a.url, undefined, loc, a.param, "https://example.com/", {});
        const t0 = Date.now();
        const r = await fetchWith(s, sub.url, { method, data: sub.body, headers: sub.headers });
        base = { status: r.status(), size: (await r.text().catch(() => "")).length, time: Date.now() - t0 };
      } catch { /* pumppet */ }
      const findings: any[] = [];
      for (const p of probes) {
        const sub = await substitute(a.url, undefined, loc, a.param, p, {});
        try {
          const t0 = Date.now();
          const r = await fetchWith(s, sub.url, { method, data: sub.body, headers: sub.headers });
          const text = await r.text().catch(() => "");
          const dt = Date.now() - t0;
          const metadataHit = /ami-id|instance-id|iam\/security-credentials|computeMetadata/i.test(text);
          const passwdHit = /root:x:0:0/.test(text);
          const differs = r.status() !== base.status || Math.abs(text.length - base.size) > Math.max(200, base.size * 0.3) || dt - base.time > 3000;
          if (metadataHit || passwdHit) findings.push({ severity: "high", payload: p, hit: metadataHit ? "cloud-metadata" : "unix-passwd", status: r.status(), snippet: text.slice(0, 400) });
          else if (differs) findings.push({ severity: "medium", payload: p, status: r.status(), size: text.length, baselineSize: base.size, timeMs: dt });
        } catch (e: any) { /* pumppet */ }
      }
      return ok({ param: a.param, baseline: base, findings });
    },
  },
  {
    name: "scan_cache_poison",
    description: "Cache-poisoning probe. Varies X-Forwarded-Host / X-Original-URL / X-Rewrite-URL and watches whether the response gets served to a clean follow-up request (indicating cache keyed only on URL).",
    schema: z.object({ url: z.string().url(), evilHost: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const evil = a.evilHost ?? "cachepoison.example";
      const headers = { "X-Forwarded-Host": evil };
      const findings: any[] = [];
      try {
        const r1 = await fetchWith(s, a.url, { method: "GET", headers });
        const b1 = (await r1.text().catch(() => "")).slice(0, 20000);
        const reflected = b1.includes(evil);
        if (!reflected) return ok({ findings: [], note: "no reflection — probably not a cache candidate" });
        await new Promise((r) => setTimeout(r, 500));
        const r2 = await fetchWith(s, a.url, { method: "GET" });
        const b2 = (await r2.text().catch(() => "")).slice(0, 20000);
        const stuck = b2.includes(evil);
        if (stuck) findings.push({ severity: "high", title: "Cache may be poisoned — evil host persists on clean request", via: "X-Forwarded-Host" });
        return ok({ reflected, stuck, findings });
      } catch (e: any) { return err(e?.message ?? String(e)); }
    },
  },
];
