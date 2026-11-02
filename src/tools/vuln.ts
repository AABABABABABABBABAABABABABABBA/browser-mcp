import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";
import { SECRET_PATTERNS, entropy, looksLikeTestOrPlaceholder } from "../patterns/secrets.js";

const sessionArg = { sessionId: z.string().optional() };

interface VersionRule {
  product: string;
  // compares x.y.z strings; returns true if the given version is <= `upToInclusive`
  upToInclusive: string;
  severity: "high" | "medium" | "low";
  note: string;
}

// Hand-curated rules (keep this list conservative; the point is to flag, not to CVE-score)
const OUTDATED: VersionRule[] = [
  { product: "PHP", upToInclusive: "5.6.40", severity: "high", note: "PHP 5.x is EOL since 2019, many unpatched CVEs" },
  { product: "PHP", upToInclusive: "7.4.33", severity: "high", note: "PHP 7.x is EOL since Nov 2022" },
  { product: "PHP", upToInclusive: "8.0.30", severity: "medium", note: "PHP 8.0 EOL since Nov 2023" },
  { product: "PHP", upToInclusive: "8.1.31", severity: "low", note: "PHP 8.1 security-only phase, upgrade recommended" },
  { product: "Apache", upToInclusive: "2.4.48", severity: "high", note: "CVE-2021-41773 / 42013 path traversal" },
  { product: "Apache", upToInclusive: "2.4.52", severity: "medium", note: "Multiple mod_proxy CVEs through 2022" },
  { product: "nginx", upToInclusive: "1.19.0", severity: "medium", note: "nginx 1.19 and earlier — several known CVEs" },
  { product: "nginx", upToInclusive: "1.22.0", severity: "low", note: "upgrade to current stable" },
  { product: "OpenSSL", upToInclusive: "1.0.2u", severity: "high", note: "OpenSSL 1.0.x EOL" },
  { product: "OpenSSL", upToInclusive: "1.1.1w", severity: "medium", note: "OpenSSL 1.1.x EOL Sept 2023" },
  { product: "jQuery", upToInclusive: "1.12.4", severity: "high", note: "jQuery <2 — many XSS CVEs" },
  { product: "jQuery", upToInclusive: "3.4.1", severity: "medium", note: "jQuery <3.5 — CVE-2020-11022/23 XSS" },
  { product: "WordPress", upToInclusive: "5.9.0", severity: "medium", note: "Core <5.9 — pre-2022 CVEs" },
  { product: "WordPress", upToInclusive: "6.2.0", severity: "low", note: "Upgrade core" },
  { product: "Bootstrap", upToInclusive: "3.4.0", severity: "medium", note: "Bootstrap 3 XSS CVEs" },
  { product: "AngularJS", upToInclusive: "1.8.3", severity: "high", note: "AngularJS 1.x is EOL (Jan 2022) — any version counts as outdated" },
  { product: "Node.js", upToInclusive: "16.20.2", severity: "medium", note: "Node 16 EOL Sept 2023" },
  { product: "Node.js", upToInclusive: "18.20.5", severity: "low", note: "Node 18 nearing EOL" },
  { product: "Lodash", upToInclusive: "4.17.20", severity: "medium", note: "Lodash <4.17.21 — prototype pollution CVEs" },
];

function cmpVersion(a: string, b: string): number {
  const pa = a.split(".").map((x) => parseInt(x, 10) || 0);
  const pb = b.split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

function matchOutdated(product: string, version: string) {
  const applicable = OUTDATED.filter((r) => r.product.toLowerCase() === product.toLowerCase());
  for (const rule of applicable) {
    if (cmpVersion(version, rule.upToInclusive) <= 0) return rule;
  }
  return null;
}

// secret patterns moved to ../patterns/secrets.ts (SECRET_PATTERNS)

export const vulnTools: ToolDef[] = [
  {
    name: "scan_outdated",
    description: "Detect server and client-side software versions and flag ones that are EOL or carry known CVEs. Looks at Server/X-Powered-By headers, generator meta tags, cookies, and version strings inside loaded JS (jQuery, lodash, WordPress, Angular, Bootstrap, Node).",
    schema: z.object({ url: z.string().url().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const target = a.url ?? s.page.url();
      const r = await s.context.request.fetch(target, { ignoreHTTPSErrors: true });
      const headers: Record<string, string> = {}; for (const { name, value } of await r.headersArray()) headers[name.toLowerCase()] = value;
      const body = (await r.text().catch(() => ""));

      const detected: Array<{ product: string; version: string; via: string }> = [];
      const push = (product: string, version: string | undefined, via: string) => { if (version) detected.push({ product, version, via }); };

      // Server header: "nginx/1.18.0", "Apache/2.4.41 (Ubuntu)"
      if (headers["server"]) {
        const m = headers["server"].match(/^([A-Za-z][\w\-]*)\/?([\d.]+)?/);
        if (m) push(m[1], m[2], "Server header");
      }
      // X-Powered-By: "PHP/7.4.3", "Express"
      if (headers["x-powered-by"]) {
        const parts = headers["x-powered-by"].split(",");
        for (const p of parts) {
          const m = p.trim().match(/^([A-Za-z][\w\-]*)\/?([\d.]+)?/);
          if (m) push(m[1], m[2], "X-Powered-By");
        }
      }
      if (headers["x-aspnet-version"]) push("ASP.NET", headers["x-aspnet-version"], "X-AspNet-Version");
      if (headers["x-aspnetmvc-version"]) push("ASP.NET MVC", headers["x-aspnetmvc-version"], "X-AspNetMvc-Version");

      // meta generator
      const genMatch = body.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
      if (genMatch) {
        const g = genMatch[1];
        const wp = g.match(/WordPress\s+([\d.]+)/i);
        if (wp) push("WordPress", wp[1], "meta generator");
        const drupal = g.match(/Drupal\s+([\d.]+)/i);
        if (drupal) push("Drupal", drupal[1], "meta generator");
        const joomla = g.match(/Joomla!?\s*-?\s*([\d.]+)/i);
        if (joomla) push("Joomla", joomla[1], "meta generator");
      }

      // PHP session cookie regardless of X-Powered-By
      if (headers["set-cookie"]?.toLowerCase().includes("phpsessid")) push("PHP", "", "PHPSESSID cookie");

      // Look at every captured JS body for library versions
      const sources = s.requests.filter((rq) => rq.responseBodySnippet).map((rq) => ({ url: rq.url, body: rq.responseBodySnippet! }));
      try { sources.push({ url: `page:${target}`, body }); } catch { /* pumppet */ }
      const JS_LIB_PATTERNS: Array<[string, RegExp]> = [
        ["jQuery", /jQuery\s+v?([\d.]+)|jquery[-.](\d+\.\d+\.\d+)/i],
        ["AngularJS", /AngularJS\s+v([\d.]+)|angular\.version\s*=\s*{\s*full\s*:\s*["']([\d.]+)/i],
        ["Angular", /@angular\/core@([\d.]+)|ng-version=["']([\d.]+)/i],
        ["React", /react-dom\.?\w*\.(\d+\.\d+\.\d+)|React\s+v?([\d.]+)/i],
        ["Vue", /Vue\.?js\s+v?([\d.]+)|vue@([\d.]+)/i],
        ["Lodash", /lodash\.(\d+\.\d+\.\d+)|lodash\s+<[^>]*>\s+([\d.]+)/i],
        ["Bootstrap", /Bootstrap\s+v?([\d.]+)|bootstrap\.(\d+\.\d+\.\d+)/i],
        ["Moment.js", /moment\.js\s+v?([\d.]+)|moment@([\d.]+)/i],
      ];
      for (const [prod, re] of JS_LIB_PATTERNS) {
        for (const src of sources) {
          const m = src.body.match(re);
          if (m) { const v = m[1] || m[2]; if (v) { push(prod, v, src.url); break; } }
        }
      }

      // Match against outdated table
      const findings: any[] = [];
      for (const d of detected) {
        if (!d.version) continue;
        const rule = matchOutdated(d.product, d.version);
        if (rule) findings.push({ severity: rule.severity, title: `${d.product} ${d.version} is outdated`, note: rule.note, via: d.via });
      }
      // version-less PHP flag
      if (detected.some((d) => d.product === "PHP" && !d.version)) {
        findings.push({ severity: "low", title: "PHP in use (version hidden) — manual version check recommended" });
      }

      return ok({ target, detected, findings });
    },
  },
  {
    name: "scan_api_keys",
    description: "Find exposed API keys / tokens / secrets in EVERY source the session has touched — page HTML, every inline <script>, every captured response body (JS/CSS/JSON/HTML/text), DOM data-* attributes, meta tags, localStorage, sessionStorage. 60+ vendor patterns (AWS/Google/Firebase/Stripe/GitHub/GitLab/Slack/Discord/Telegram/Twilio/Mailgun/SendGrid/PayPal/Shopify/Dropbox/Heroku/DigitalOcean/OpenAI/Anthropic/HuggingFace/Mapbox/Sentry/NewRelic/Datadog/npm/PyPI/Vercel/Netlify/Cloudflare/Supabase/Twitter/Facebook) plus context-aware detection (apiKey: \"...\"), env-style assignments, DB connection strings with embedded creds, PEM/PGP/age keys, and a configurable entropy heuristic for anonymous high-entropy strings sitting near secret-ish identifiers.",
    schema: z.object({
      includeDOM: z.boolean().optional().describe("default true — also sweeps data-* attrs, meta tags, localStorage, sessionStorage"),
      entropyThreshold: z.number().optional().describe("flag high-entropy strings (bits/char) >= this when near 'api/token/secret/password' words; default 4.5, set 0 to disable"),
      includeTestKeys: z.boolean().optional().describe("default false — hide known test/example placeholders like AKIAIOSFODNN7EXAMPLE"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const sources: Array<{ url: string; body: string }> = [];
      try { sources.push({ url: `page:${s.page.url()}`, body: await s.page.content() }); } catch { /* pumppet */ }
      for (const r of s.requests) if (r.responseBodySnippet) sources.push({ url: r.url, body: r.responseBodySnippet });

      if (a.includeDOM !== false) {
        try {
          const dom = await s.page.evaluate(() => {
            const out: Array<{ where: string; text: string }> = [];
            for (const el of Array.from(document.querySelectorAll("[data-key],[data-token],[data-secret],[data-api],[data-apikey],[data-auth]"))) {
              for (const at of Array.from((el as any).attributes)) if ((at as any).name.startsWith("data-")) out.push({ where: `dom[${el.tagName.toLowerCase()}][${(at as any).name}]`, text: (at as any).value });
            }
            for (const m of Array.from(document.querySelectorAll('meta[name*="key" i],meta[name*="token" i],meta[name*="api" i]'))) out.push({ where: `meta[${(m as any).name}]`, text: (m as any).content });
            for (const sc of Array.from(document.querySelectorAll("script:not([src])"))) out.push({ where: "inline-script", text: sc.textContent ?? "" });
            try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i)!; out.push({ where: `localStorage[${k}]`, text: localStorage.getItem(k) ?? "" }); } } catch {}
            try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i)!; out.push({ where: `sessionStorage[${k}]`, text: sessionStorage.getItem(k) ?? "" }); } } catch {}
            return out;
          });
          for (const d of dom) if (d.text) sources.push({ url: d.where, body: d.text });
        } catch { /* pumppet */ }
      }

      const findings: any[] = [];
      const seen = new Set<string>();
      for (const src of sources) {
        for (const pat of SECRET_PATTERNS) {
          pat.re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = pat.re.exec(src.body))) {
            const captured = pat.group !== undefined ? m[pat.group] : m[0];
            if (!captured) continue;
            if (pat.near) {
              const ctxStart = Math.max(0, m.index - 60);
              const ctxEnd = Math.min(src.body.length, m.index + m[0].length + 60);
              if (!pat.near.test(src.body.slice(ctxStart, ctxEnd))) continue;
            }
            if (!a.includeTestKeys && looksLikeTestOrPlaceholder(captured)) continue;
            const key = `${pat.name}:${captured}:${src.url}`;
            if (seen.has(key)) continue; seen.add(key);
            findings.push({
              severity: pat.severity,
              type: pat.name,
              match: captured.length > 100 ? captured.slice(0, 80) + "…" : captured,
              source: src.url,
              context: src.body.slice(Math.max(0, m.index - 40), m.index + m[0].length + 40).replace(/\s+/g, " "),
            });
          }
        }
      }

      const entThreshold = a.entropyThreshold ?? 4.5;
      if (entThreshold > 0) {
        const ENTRE = /["'`]([A-Za-z0-9+/=_\-]{32,200})["'`]/g;
        const CTX_WORDS = /\b(api[_\- ]?key|apikey|token|secret|password|auth|bearer|credentials)\b/i;
        for (const src of sources) {
          ENTRE.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = ENTRE.exec(src.body))) {
            const val = m[1];
            if (val.length < 32) continue;
            if (!a.includeTestKeys && looksLikeTestOrPlaceholder(val)) continue;
            if (entropy(val) < entThreshold) continue;
            const ctxStart = Math.max(0, m.index - 60);
            const ctxEnd = Math.min(src.body.length, m.index + m[0].length + 60);
            const ctx = src.body.slice(ctxStart, ctxEnd);
            if (!CTX_WORDS.test(ctx)) continue;
            const key = `entropy:${val}:${src.url}`;
            if (seen.has(key)) continue; seen.add(key);
            findings.push({
              severity: "medium",
              type: "High-entropy string near secret-ish identifier",
              match: val.length > 100 ? val.slice(0, 80) + "…" : val,
              source: src.url,
              entropy: Math.round(entropy(val) * 100) / 100,
              context: ctx.replace(/\s+/g, " "),
            });
          }
        }
      }

      const summary = { high: 0, medium: 0, low: 0 } as Record<string, number>;
      for (const f of findings) summary[f.severity]++;
      return ok({ count: findings.length, summary, findings });
    },
  },
  {
    name: "scan_js_secrets",
    description: "Alias for scan_api_keys (kept for backward compat).",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const fn = vulnTools.find((t) => t.name === "scan_api_keys")!;
      return fn.handler({ ...a });
    },
  },
  {
    name: "scan_sensitive_files",
    description: "Expanded sensitive-file probe. Looks for VCS leaks (.git/HEAD, .svn), env files, backup dumps, config files, admin consoles, PHP info, actuator endpoints, etc.",
    schema: z.object({ baseUrl: z.string().url(), concurrency: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const base = a.baseUrl.replace(/\/$/, "");
      const files = [
        ".git/HEAD", ".git/config", ".git/index", ".gitignore",
        ".svn/entries", ".hg/hgrc", ".bzr/README",
        ".env", ".env.local", ".env.production", ".env.development", ".env.backup",
        "config.php", "wp-config.php", "wp-config.php.bak", "wp-config.old",
        "config.yaml", "config.yml", "config.json", "application.yml", "application.properties",
        "docker-compose.yml", "Dockerfile", ".dockerignore",
        "database.sql", "db.sql", "dump.sql", "backup.sql", "mysql.sql",
        "backup.zip", "backup.tar.gz", "site.zip", "www.zip", "html.zip",
        "phpinfo.php", "info.php", "test.php", "temp.php", "admin.php",
        "server-status", "server-info",
        "actuator", "actuator/env", "actuator/health", "actuator/mappings",
        "console", "console/", "jmx-console/", "web-console/",
        ".idea/workspace.xml", ".vscode/settings.json",
        ".DS_Store", "Thumbs.db",
        "composer.json", "composer.lock", "package.json", "yarn.lock", "pnpm-lock.yaml", "Gemfile", "requirements.txt",
        "readme.html", "license.txt", "CHANGELOG.md",
        "robots.txt", "sitemap.xml", "sitemap_index.xml",
        "crossdomain.xml", "clientaccesspolicy.xml", ".well-known/security.txt",
      ];
      const concurrency = Math.min(a.concurrency ?? 10, 20);
      const results: any[] = []; let i = 0;
      const SIGS: Array<[string, RegExp]> = [
        [".git/HEAD", /^ref:\s+refs\//m],
        [".env", /^[A-Z_]+=/m],
        ["sql dump", /^-- MySQL dump|CREATE TABLE/mi],
        ["phpinfo", /phpinfo\(\)|PHP Version/i],
        ["actuator", /"status"\s*:\s*"UP"|contexts/i],
      ];
      const worker = async () => {
        while (i < files.length) {
          const f = files[i++];
          const url = `${base}/${f}`;
          try {
            const r = await s.context.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 0 });
            if (r.status() === 404) continue;
            const text = (await r.text().catch(() => "")).slice(0, 2000);
            const sigHit = SIGS.find(([, re]) => re.test(text));
            results.push({ file: f, url, status: r.status(), size: text.length, snippet: text.slice(0, 300), confirmed: !!sigHit, signature: sigHit?.[0] });
          } catch { /* pumppet */ }
        }
      };
      await Promise.all(Array.from({ length: concurrency }, () => worker()));
      const findings = results.filter((r) => r.confirmed || (r.status === 200 && r.size > 50))
        .map((r) => ({ severity: r.confirmed ? "high" : "medium", title: `Accessible: ${r.file}${r.confirmed ? " (content confirmed)" : ""}`, file: r.file, status: r.status, snippet: r.snippet.slice(0, 160) }));
      return ok({ tried: files.length, hits: results.length, findings });
    },
  },
  {
    name: "scan_backup_variants",
    description: "For a given URL, try common backup/variant extensions on it (foo.php → foo.php.bak, foo.php~, foo.php.old, foo.zip, foo.tar.gz). Useful once you've mapped a site.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const u = new URL(a.url);
      const path = u.pathname;
      const base = u.origin + path;
      const dirPart = path.replace(/\/[^/]*$/, "/");
      const lastSeg = (path.split("/").pop() || "index").replace(/\.[^.]*$/, "");
      const ext = (path.match(/\.([^./]+)$/)?.[1] ?? "");
      const candidates = new Set<string>();
      const addVariants = (p: string) => {
        candidates.add(`${p}.bak`); candidates.add(`${p}~`); candidates.add(`${p}.old`); candidates.add(`${p}.orig`); candidates.add(`${p}.swp`); candidates.add(`${p}.save`); candidates.add(`.${p.split("/").pop()}.swp`); candidates.add(`${p}.1`);
      };
      addVariants(base);
      if (ext) {
        candidates.add(`${base.slice(0, -ext.length - 1)}.bak.${ext}`);
        candidates.add(`${u.origin}${dirPart}${lastSeg}.zip`);
        candidates.add(`${u.origin}${dirPart}${lastSeg}.tar.gz`);
        candidates.add(`${u.origin}${dirPart}${lastSeg}.tgz`);
      }
      const results: any[] = [];
      for (const c of candidates) {
        try {
          const r = await s.context.request.fetch(c, { ignoreHTTPSErrors: true, maxRedirects: 0 });
          if (r.status() === 404) continue;
          const t = (await r.text().catch(() => "")).slice(0, 400);
          results.push({ url: c, status: r.status(), snippet: t });
        } catch { /* pumppet */ }
      }
      return ok({ tried: candidates.size, hits: results, findings: results.filter((r) => r.status === 200).map((r) => ({ severity: "high", title: `Backup/variant accessible: ${r.url}` })) });
    },
  },
  {
    name: "scan_methods",
    description: "Test which HTTP methods an endpoint accepts (OPTIONS, GET, POST, PUT, DELETE, PATCH, HEAD, TRACE). Flags dangerous ones like PUT/DELETE/TRACE accepting without auth.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const methods = ["OPTIONS", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "TRACE"];
      const results: any[] = [];
      for (const m of methods) {
        try {
          const r = await s.context.request.fetch(a.url, { method: m, ignoreHTTPSErrors: true, maxRedirects: 0 });
          results.push({ method: m, status: r.status(), allow: r.headers()["allow"] ?? null });
        } catch (e: any) { results.push({ method: m, error: e?.message ?? String(e) }); }
      }
      const findings: any[] = [];
      for (const r of results) {
        if (["PUT", "DELETE", "TRACE", "PATCH"].includes(r.method) && r.status && r.status < 400) {
          findings.push({ severity: r.method === "TRACE" ? "high" : "medium", title: `${r.method} ${a.url} returned ${r.status}` });
        }
      }
      return ok({ results, findings });
    },
  },
  {
    name: "scan_rate_limit",
    description: "Fire N parallel requests at an endpoint, report whether throttling kicks in (429 / RateLimit headers / dropping success rate).",
    schema: z.object({ url: z.string().url(), count: z.number().int().min(2).max(100).optional(), concurrency: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const total = a.count ?? 25;
      const concurrency = Math.min(a.concurrency ?? 10, total);
      const results: any[] = []; let i = 0;
      const worker = async () => {
        while (i < total) {
          const idx = i++;
          const t0 = Date.now();
          try {
            const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
            const h = r.headers();
            results[idx] = { status: r.status(), ms: Date.now() - t0, rateLimit: h["x-ratelimit-remaining"] ?? h["ratelimit-remaining"] ?? null, retryAfter: h["retry-after"] ?? null };
          } catch (e: any) { results[idx] = { error: e?.message ?? String(e) }; }
        }
      };
      await Promise.all(Array.from({ length: concurrency }, () => worker()));
      const got429 = results.some((r) => r.status === 429);
      const hadRLH = results.some((r) => r.rateLimit);
      const findings: any[] = [];
      if (!got429 && !hadRLH) findings.push({ severity: "medium", title: `No rate-limiting observed over ${total} requests` });
      return ok({ total, got429, hadRateLimitHeader: hadRLH, results, findings });
    },
  },
];
