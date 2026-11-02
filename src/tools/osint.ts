import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

async function head(session: ReturnType<typeof hub.getSession>, url: string) {
  try { const r = await session.context.request.fetch(url, { method: "HEAD", ignoreHTTPSErrors: true, maxRedirects: 2 }); return { status: r.status(), headers: r.headers() }; }
  catch { return null; }
}

// Common username-check targets (profile URL template → signal of "exists")
const USER_SITES: Array<{ site: string; url: (u: string) => string; existsStatus?: number[]; notBody?: RegExp }> = [
  { site: "github", url: (u) => `https://github.com/${u}`, existsStatus: [200], notBody: /Page not found/i },
  { site: "twitter", url: (u) => `https://twitter.com/${u}`, existsStatus: [200] },
  { site: "instagram", url: (u) => `https://instagram.com/${u}/`, existsStatus: [200], notBody: /Page not found/i },
  { site: "tiktok", url: (u) => `https://www.tiktok.com/@${u}`, existsStatus: [200], notBody: /Couldn't find this account/i },
  { site: "reddit", url: (u) => `https://www.reddit.com/user/${u}/about.json`, existsStatus: [200] },
  { site: "youtube", url: (u) => `https://www.youtube.com/@${u}`, existsStatus: [200], notBody: /This page isn't available/i },
  { site: "medium", url: (u) => `https://medium.com/@${u}`, existsStatus: [200] },
  { site: "dev.to", url: (u) => `https://dev.to/${u}`, existsStatus: [200], notBody: /404 Page Not Found/i },
  { site: "hashnode", url: (u) => `https://hashnode.com/@${u}`, existsStatus: [200] },
  { site: "about.me", url: (u) => `https://about.me/${u}`, existsStatus: [200], notBody: /not found/i },
  { site: "gitlab", url: (u) => `https://gitlab.com/${u}`, existsStatus: [200] },
  { site: "bitbucket", url: (u) => `https://bitbucket.org/${u}/`, existsStatus: [200] },
  { site: "roblox-profile", url: (u) => `https://www.roblox.com/users/profile?username=${u}`, existsStatus: [200] },
  { site: "steam", url: (u) => `https://steamcommunity.com/id/${u}/`, existsStatus: [200], notBody: /The specified profile could not be found/i },
  { site: "twitch", url: (u) => `https://www.twitch.tv/${u}`, existsStatus: [200] },
  { site: "patreon", url: (u) => `https://www.patreon.com/${u}`, existsStatus: [200], notBody: /sorry, we couldn't find/i },
  { site: "spotify", url: (u) => `https://open.spotify.com/user/${u}`, existsStatus: [200] },
  { site: "soundcloud", url: (u) => `https://soundcloud.com/${u}`, existsStatus: [200] },
  { site: "pinterest", url: (u) => `https://www.pinterest.com/${u}/`, existsStatus: [200] },
  { site: "linkedin-pub", url: (u) => `https://www.linkedin.com/in/${u}/`, existsStatus: [200] },
  { site: "keybase", url: (u) => `https://keybase.io/${u}`, existsStatus: [200] },
  { site: "producthunt", url: (u) => `https://www.producthunt.com/@${u}`, existsStatus: [200] },
  { site: "hackernews", url: (u) => `https://news.ycombinator.com/user?id=${u}`, existsStatus: [200], notBody: /No such user/i },
  { site: "goodreads", url: (u) => `https://www.goodreads.com/user/show/${u}`, existsStatus: [200] },
  { site: "last.fm", url: (u) => `https://www.last.fm/user/${u}`, existsStatus: [200], notBody: /Whoops|not found/i },
];

export const osintTools: ToolDef[] = [
  {
    name: "osint_username_sweep",
    description: "Sherlock-style username sweep across 20+ social / dev / gaming / music sites. Reports where that username exists.",
    schema: z.object({
      username: z.string(),
      sites: z.array(z.string()).optional().describe("subset of site names"),
      concurrency: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const list = a.sites ? USER_SITES.filter((x) => a.sites!.includes(x.site)) : USER_SITES;
      const concurrency = Math.min(a.concurrency ?? 8, 15);
      let i = 0; const results: any[] = [];
      const worker = async () => {
        while (i < list.length) {
          const site = list[i++];
          const url = site.url(a.username);
          try {
            const r = await s.context.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 2, headers: { "User-Agent": "Mozilla/5.0" } });
            const body = site.notBody ? (await r.text().catch(() => "")).slice(0, 10000) : "";
            const existsByCode = site.existsStatus ? site.existsStatus.includes(r.status()) : r.status() < 400;
            const notFoundByBody = site.notBody && site.notBody.test(body);
            const exists = existsByCode && !notFoundByBody;
            results.push({ site: site.site, url, status: r.status(), exists });
          } catch { results.push({ site: site.site, url, exists: false, error: "net" }); }
        }
      };
      await Promise.all(Array.from({ length: concurrency }, () => worker()));
      return ok({ username: a.username, found: results.filter((r) => r.exists), notFound: results.filter((r) => !r.exists).length, results });
    },
  },
  {
    name: "osint_email_guess",
    description: "Generate the common corporate email formats for a given name + domain (first, first.last, flast, etc.) — useful for cold outreach / recon.",
    schema: z.object({ firstName: z.string(), lastName: z.string(), domain: z.string() }),
    handler: async (a) => {
      const f = a.firstName.toLowerCase(), l = a.lastName.toLowerCase(), d = a.domain.toLowerCase();
      const candidates = [
        `${f}@${d}`, `${l}@${d}`, `${f}.${l}@${d}`, `${f}_${l}@${d}`, `${f}${l}@${d}`,
        `${f[0]}${l}@${d}`, `${f}${l[0]}@${d}`, `${f[0]}.${l}@${d}`, `${l}.${f}@${d}`, `${l}${f[0]}@${d}`,
        `${f[0]}_${l}@${d}`, `${f}-${l}@${d}`, `${f[0]}${l[0]}@${d}`,
      ];
      return ok({ candidates: Array.from(new Set(candidates)) });
    },
  },
  {
    name: "osint_breach_patterns",
    description: "Given a password, check it against local common-password lists + simple patterns (date-of-birth style, dictionary + 1234, keyboard rows). This is NOT a HIBP lookup.",
    schema: z.object({ password: z.string() }),
    handler: async (a) => {
      const findings: string[] = [];
      const p = a.password;
      if (/\b(19|20)\d{2}\b/.test(p)) findings.push("contains a year 1900-2099 (date-of-birth pattern)");
      if (/(qwerty|asdf|zxcv|1234|password|letmein|welcome)/i.test(p)) findings.push("contains common keyboard/sequence/dict pattern");
      if (/^(.)\1{3,}$/.test(p)) findings.push("same char repeated");
      if (p.length < 8) findings.push("length < 8");
      if (!/[A-Z]/.test(p)) findings.push("no uppercase");
      if (!/\d/.test(p)) findings.push("no digit");
      if (!/[^A-Za-z0-9]/.test(p)) findings.push("no symbol");
      return ok({ password: p, risky: findings.length > 2, findings });
    },
  },
  {
    name: "osint_ip_lookup",
    description: "Public IP geolocation / ASN via ip-api.com (free, no key).",
    schema: z.object({ ip: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const r = await s.context.request.fetch(`http://ip-api.com/json/${encodeURIComponent(a.ip)}?fields=66846719`, { ignoreHTTPSErrors: true });
        return ok(JSON.parse(await r.text()));
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "osint_whois_rdap",
    description: "WHOIS lookup via RDAP (JSON) for a domain.",
    schema: z.object({ domain: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const r = await s.context.request.fetch(`https://rdap.org/domain/${encodeURIComponent(a.domain)}`, { ignoreHTTPSErrors: true });
        if (r.status() >= 400) return ok({ status: r.status(), note: "no RDAP record" });
        const j = JSON.parse(await r.text());
        const entity = (j.entities ?? []).map((e: any) => ({ roles: e.roles, vcard: e.vcardArray?.[1]?.filter((x: any) => x[0] === "fn" || x[0] === "email" || x[0] === "org").map((x: any) => ({ [x[0]]: x[3] })) }));
        return ok({ handle: j.handle, name: j.ldhName, status: j.status, events: j.events, nameservers: (j.nameservers ?? []).map((n: any) => n.ldhName), entities: entity });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "osint_shorten_unroll",
    description: "Follow redirects on a shortened URL (bit.ly, t.co, goo.gl, tinyurl, …) and return the full chain + final destination.",
    schema: z.object({ url: z.string().url(), max: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const chain: Array<{ url: string; status: number }> = [{ url: a.url, status: 0 }];
      let cur = a.url;
      for (let i = 0; i < (a.max ?? 10); i++) {
        try {
          const r = await s.context.request.fetch(cur, { method: "HEAD", maxRedirects: 0, ignoreHTTPSErrors: true });
          chain[chain.length - 1].status = r.status();
          const loc = r.headers()["location"];
          if (!loc) break;
          cur = new URL(loc, cur).toString(); chain.push({ url: cur, status: 0 });
        } catch { break; }
      }
      return ok({ chain, final: cur });
    },
  },
  {
    name: "osint_pastebin_search",
    description: "Search Google for leaks on common paste-sites (pastebin.com, ghostbin.co, controlc.com, rentry.co). Returns top matches.",
    schema: z.object({ q: z.string(), ...sessionArg }),
    handler: async (a) => {
      const query = `${a.q} (site:pastebin.com OR site:ghostbin.co OR site:controlc.com OR site:rentry.co OR site:paste.ee)`;
      const search = (await import("./search.js")).searchTools.find((t) => t.name === "search_web")!;
      const res = await search.handler({ q: query, limit: 20, sessionId: a.sessionId });
      return res as any;
    },
  },
  {
    name: "osint_github_user",
    description: "Public GitHub user info — repos, followers, bio, emails from commits (via /users/<name>/events).",
    schema: z.object({ username: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const user = JSON.parse(await (await s.context.request.fetch(`https://api.github.com/users/${encodeURIComponent(a.username)}`, { ignoreHTTPSErrors: true })).text());
        const events = JSON.parse(await (await s.context.request.fetch(`https://api.github.com/users/${encodeURIComponent(a.username)}/events/public?per_page=100`, { ignoreHTTPSErrors: true })).text());
        const emails = new Set<string>();
        for (const e of (events ?? [])) if (e?.payload?.commits) for (const c of e.payload.commits) if (c.author?.email && !c.author.email.endsWith("users.noreply.github.com")) emails.add(c.author.email);
        return ok({ user: { login: user.login, name: user.name, bio: user.bio, company: user.company, blog: user.blog, location: user.location, email: user.email, twitter: user.twitter_username, publicRepos: user.public_repos, followers: user.followers, following: user.following, created: user.created_at }, leakedEmails: Array.from(emails) });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "osint_dns_history_crtsh",
    description: "Pull every SAN (subject-alternative-name) ever issued for a domain in the public CT log via crt.sh.",
    schema: z.object({ domain: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(`https://crt.sh/?q=%25.${encodeURIComponent(a.domain)}&output=json`, { ignoreHTTPSErrors: true, timeout: 30000 } as any);
      try {
        const arr = JSON.parse(await r.text());
        const names = new Set<string>();
        for (const row of arr) if (row.name_value) for (const n of row.name_value.split("\n")) names.add(n.trim());
        return ok({ count: names.size, names: Array.from(names).sort() });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "osint_robots_fingerprint",
    description: "Fetch /robots.txt and classify likely tech stack / sensitive paths it hints at.",
    schema: z.object({ baseUrl: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.baseUrl.replace(/\/$/, "") + "/robots.txt", { ignoreHTTPSErrors: true });
      const text = await r.text().catch(() => "");
      if (r.status() >= 400) return ok({ note: "no robots.txt" });
      const disallows = Array.from(text.matchAll(/Disallow:\s*(.+)/gi)).map((m) => m[1].trim());
      const sitemap = /Sitemap:\s*(\S+)/i.exec(text)?.[1];
      const hints: string[] = [];
      if (disallows.some((d) => /wp-admin|wp-login/.test(d))) hints.push("WordPress");
      if (disallows.some((d) => /\/sites\/default\/files/.test(d))) hints.push("Drupal");
      if (disallows.some((d) => /\/admin\/|\/admin$/.test(d))) hints.push("has /admin");
      if (disallows.some((d) => /\/api\//.test(d))) hints.push("has /api");
      if (disallows.some((d) => /\/node\//.test(d))) hints.push("Drupal node");
      return ok({ sitemap, disallows, hints });
    },
  },
];
