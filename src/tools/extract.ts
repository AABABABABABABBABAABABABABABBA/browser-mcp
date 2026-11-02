import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

function stripTags(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>|<\/div>|<\/li>|<\/h\d>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#(\d+);/g, (_m, n) => String.fromCharCode(+n))
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function htmlToMarkdown(html: string): string {
  let md = html;
  md = md.replace(/<script[\s\S]*?<\/script>/gi, "");
  md = md.replace(/<style[\s\S]*?<\/style>/gi, "");
  md = md.replace(/<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi, (_m, l, c) => `\n${"#".repeat(+l)} ${stripTags(c)}\n`);
  md = md.replace(/<strong[^>]*>([\s\S]*?)<\/strong>/gi, "**$1**");
  md = md.replace(/<b[^>]*>([\s\S]*?)<\/b>/gi, "**$1**");
  md = md.replace(/<em[^>]*>([\s\S]*?)<\/em>/gi, "*$1*");
  md = md.replace(/<i[^>]*>([\s\S]*?)<\/i>/gi, "*$1*");
  md = md.replace(/<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi, "[$2]($1)");
  md = md.replace(/<img[^>]+src="([^"]+)"[^>]*>/gi, "![]($1)");
  md = md.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, "- $1\n");
  md = md.replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, "`$1`");
  md = md.replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, "\n```\n$1\n```\n");
  md = md.replace(/<p[^>]*>/gi, "\n").replace(/<\/p>/gi, "\n");
  md = md.replace(/<br\s*\/?>/gi, "\n");
  md = stripTags(md);
  return md.replace(/\n{3,}/g, "\n\n").trim();
}

function readabilityExtract(html: string): { title: string | null; text: string } {
  // Prefer <article>; fall back to <main>; else pick the div with the highest text density
  const article = /<article[\s\S]*?<\/article>/i.exec(html)?.[0];
  const main = /<main[\s\S]*?<\/main>/i.exec(html)?.[0];
  let candidate = article ?? main;
  if (!candidate) {
    const divs = Array.from(html.matchAll(/<div[\s\S]*?<\/div>/gi));
    let bestScore = 0;
    for (const d of divs) {
      const text = stripTags(d[0]);
      const links = (d[0].match(/<a /g) ?? []).length;
      const score = text.length - links * 50;
      if (score > bestScore) { bestScore = score; candidate = d[0]; }
    }
  }
  const title = /<title>([\s\S]*?)<\/title>/i.exec(html)?.[1]?.trim() ?? /<h1[^>]*>([\s\S]*?)<\/h1>/i.exec(html)?.[1]?.trim() ?? null;
  return { title: title ? stripTags(title) : null, text: stripTags(candidate ?? html) };
}

export const extractTools: ToolDef[] = [
  {
    name: "extract_article",
    description: "Readability-style article extraction. Fetches a URL and returns the clean body text + title (strips nav/ads/scripts).",
    schema: z.object({ url: z.string().url(), maxChars: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const html = (await r.text().catch(() => "")).slice(0, 2000000);
      const { title, text } = readabilityExtract(html);
      const cap = a.maxChars ?? 20000;
      return ok({ url: a.url, title, text: text.slice(0, cap), truncated: text.length > cap, length: text.length });
    },
  },
  {
    name: "extract_markdown",
    description: "Fetch a URL and convert its HTML to clean Markdown.",
    schema: z.object({ url: z.string().url(), maxChars: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const html = (await r.text().catch(() => "")).slice(0, 2000000);
      const md = htmlToMarkdown(html);
      const cap = a.maxChars ?? 20000;
      return ok({ url: a.url, markdown: md.slice(0, cap), truncated: md.length > cap, length: md.length });
    },
  },
  {
    name: "extract_meta",
    description: "Extract every <meta>, Open Graph, Twitter Card, favicon, canonical, and JSON-LD block from a URL.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const html = (await r.text().catch(() => "")).slice(0, 1000000);
      const metas: any[] = [];
      const metaRe = /<meta\s+[^>]*>/gi; let m: RegExpExecArray | null;
      while ((m = metaRe.exec(html))) {
        const tag = m[0];
        const name = /name="([^"]+)"/i.exec(tag)?.[1] ?? /property="([^"]+)"/i.exec(tag)?.[1] ?? /http-equiv="([^"]+)"/i.exec(tag)?.[1];
        const content = /content="([^"]+)"/i.exec(tag)?.[1];
        if (name && content) metas.push({ name, content });
      }
      const og: Record<string, string> = {}, tw: Record<string, string> = {};
      for (const m of metas) {
        if (m.name.startsWith("og:")) og[m.name.slice(3)] = m.content;
        if (m.name.startsWith("twitter:")) tw[m.name.slice(8)] = m.content;
      }
      const canonical = /<link\s+rel="canonical"\s+href="([^"]+)"/i.exec(html)?.[1];
      const favicons = Array.from(html.matchAll(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["']/gi)).map((m: any) => m[1]);
      const jsonld = Array.from(html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)).map((m: any) => { try { return JSON.parse(m[1]); } catch { return null; } }).filter(Boolean);
      return ok({ url: a.url, title: /<title>([\s\S]*?)<\/title>/i.exec(html)?.[1]?.trim(), canonical, favicons, meta: metas, og, twitter: tw, jsonLd: jsonld });
    },
  },
  {
    name: "extract_feed",
    description: "Parse an RSS 2.0 or Atom feed into { title, items: [...] }.",
    schema: z.object({ url: z.string().url(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const xml = await r.text().catch(() => "");
      const items: any[] = [];
      if (/<rss/i.test(xml)) {
        const re = /<item>([\s\S]*?)<\/item>/g; let m: RegExpExecArray | null;
        while ((m = re.exec(xml)) && items.length < (a.limit ?? 20)) {
          const b = m[1];
          items.push({
            title: stripTags(/<title>([\s\S]*?)<\/title>/.exec(b)?.[1] ?? ""),
            link: /<link>([\s\S]*?)<\/link>/.exec(b)?.[1]?.trim(),
            pubDate: /<pubDate>([\s\S]*?)<\/pubDate>/.exec(b)?.[1],
            description: stripTags((/<description>([\s\S]*?)<\/description>/.exec(b)?.[1] ?? "").slice(0, 500)),
          });
        }
      } else if (/<feed/i.test(xml)) {
        const re = /<entry[\s\S]*?<\/entry>/g; let m: RegExpExecArray | null;
        while ((m = re.exec(xml)) && items.length < (a.limit ?? 20)) {
          const b = m[0];
          items.push({
            title: stripTags(/<title[^>]*>([\s\S]*?)<\/title>/.exec(b)?.[1] ?? ""),
            link: /<link[^>]*href="([^"]+)"/.exec(b)?.[1],
            updated: /<updated>([\s\S]*?)<\/updated>/.exec(b)?.[1],
            summary: stripTags((/<summary[^>]*>([\s\S]*?)<\/summary>/.exec(b)?.[1] ?? "").slice(0, 500)),
          });
        }
      } else return err("not an RSS or Atom feed");
      const title = /<title>([\s\S]*?)<\/title>/.exec(xml)?.[1];
      return ok({ title: title ? stripTags(title) : null, count: items.length, items });
    },
  },
  {
    name: "extract_text_from_url",
    description: "Plain-text extraction from a URL (lighter than extract_article; just strips all markup).",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const html = (await r.text().catch(() => "")).slice(0, 2000000);
      return ok({ url: a.url, text: stripTags(html).slice(0, 50000) });
    },
  },
  {
    name: "extract_tables",
    description: "Pull every <table> from a URL into a structured list of header+rows.",
    schema: z.object({ url: z.string().url(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const html = await r.text().catch(() => "");
      const tables: any[] = [];
      const tre = /<table[\s\S]*?<\/table>/gi; let m: RegExpExecArray | null;
      while ((m = tre.exec(html)) && tables.length < (a.limit ?? 10)) {
        const t = m[0];
        const rows = Array.from(t.matchAll(/<tr[\s\S]*?<\/tr>/gi)).map((r: any) => Array.from(r[0].matchAll(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi)).map((c: any) => stripTags(c[1])));
        if (rows.length) tables.push({ rowCount: rows.length, headers: rows[0], rows: rows.slice(1) });
      }
      return ok({ count: tables.length, tables });
    },
  },
  {
    name: "extract_links",
    description: "Every link on a page: text, href (resolved), rel, target. Doesn't need the browser — straight HTTP fetch.",
    schema: z.object({ url: z.string().url(), sameOriginOnly: z.boolean().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const html = await r.text().catch(() => "");
      const origin = new URL(a.url).origin;
      const links: any[] = [];
      const re = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi; let m: RegExpExecArray | null;
      while ((m = re.exec(html))) {
        let href = m[1];
        try { href = new URL(href, a.url).toString(); } catch { continue; }
        if (a.sameOriginOnly && !href.startsWith(origin)) continue;
        links.push({ text: stripTags(m[2]).slice(0, 120), href });
      }
      return ok({ count: links.length, links });
    },
  },
  {
    name: "extract_emails",
    description: "Pull every email address from a URL or raw text.",
    schema: z.object({ url: z.string().url().optional(), text: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      let body = a.text;
      if (a.url) { const s = hub.getSession(a.sessionId); const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true }); body = (await r.text().catch(() => "")); }
      if (!body) return err("provide url or text");
      const emails = Array.from(new Set(Array.from(body.matchAll(/[\w.+-]+@[\w-]+\.[\w.-]{2,24}/g)).map((m: any) => m[0])));
      return ok({ count: emails.length, emails });
    },
  },
  {
    name: "extract_phones",
    description: "Pull phone-number-looking strings from a URL or text.",
    schema: z.object({ url: z.string().url().optional(), text: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      let body = a.text;
      if (a.url) { const s = hub.getSession(a.sessionId); const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true }); body = (await r.text().catch(() => "")); }
      if (!body) return err("provide url or text");
      const phones = Array.from(new Set(Array.from(body.matchAll(/(?:\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g)).map((m: any) => m[0].trim())));
      return ok({ count: phones.length, phones });
    },
  },
  {
    name: "extract_social_handles",
    description: "Extract social-media handles / profile URLs from a page or text (Twitter/X, GitHub, Instagram, TikTok, LinkedIn, YouTube, Facebook, Mastodon).",
    schema: z.object({ url: z.string().url().optional(), text: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      let body = a.text;
      if (a.url) { const s = hub.getSession(a.sessionId); const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true }); body = (await r.text().catch(() => "")); }
      if (!body) return err("provide url or text");
      const sites: Record<string, RegExp> = {
        twitter: /(?:https?:\/\/)?(?:www\.)?(?:twitter|x)\.com\/([A-Za-z0-9_]{1,15})(?![\w\/])/g,
        github: /(?:https?:\/\/)?github\.com\/([A-Za-z0-9-]{1,39})(?![\w\/])/g,
        instagram: /(?:https?:\/\/)?instagram\.com\/([A-Za-z0-9_.]{1,30})(?![\w\/])/g,
        tiktok: /(?:https?:\/\/)?(?:www\.)?tiktok\.com\/@([A-Za-z0-9_.]{1,24})/g,
        linkedin: /(?:https?:\/\/)?(?:www\.)?linkedin\.com\/(?:in|company)\/([A-Za-z0-9-]{1,100})/g,
        youtube: /(?:https?:\/\/)?(?:www\.)?youtube\.com\/(?:@|channel\/|c\/|user\/)([A-Za-z0-9_-]{1,30})/g,
        facebook: /(?:https?:\/\/)?(?:www\.)?facebook\.com\/([A-Za-z0-9.-]{1,50})(?![\w\/])/g,
        mastodon: /@[A-Za-z0-9_]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
      };
      const out: Record<string, string[]> = {};
      for (const [name, re] of Object.entries(sites)) out[name] = Array.from(new Set(Array.from(body.matchAll(re)).map((m: any) => m[1] ?? m[0])));
      return ok(out);
    },
  },
  {
    name: "extract_wayback",
    description: "Query the Internet Archive Wayback Machine for snapshots of a URL. Returns snapshot timestamps + URLs.",
    schema: z.object({ url: z.string().url(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const api = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(a.url)}&output=json&limit=${a.limit ?? 25}&fl=timestamp,original,statuscode,mimetype&from=20000101`;
      const r = await s.context.request.fetch(api, { ignoreHTTPSErrors: true });
      try {
        const arr = JSON.parse(await r.text());
        if (!arr.length) return ok({ snapshots: [] });
        const [headers, ...rows] = arr;
        const snaps = rows.map((row: any[]) => Object.fromEntries(headers.map((h: string, i: number) => [h, row[i]])));
        return ok({ count: snaps.length, snapshots: snaps.map((s: any) => ({ ...s, archiveUrl: `https://web.archive.org/web/${s.timestamp}/${s.original}` })) });
      } catch { return err("parse failed"); }
    },
  },
  {
    name: "extract_wayback_latest",
    description: "Get the most recent Wayback Machine snapshot URL for a page.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(a.url)}`, { ignoreHTTPSErrors: true });
      try { const j = JSON.parse(await r.text()); return ok(j.archived_snapshots?.closest ?? { note: "no snapshot" }); }
      catch { return err("parse failed"); }
    },
  },
  {
    name: "extract_opengraph_card",
    description: "Build a social-share preview card (title, description, image, site) for a URL.",
    schema: z.object({ url: z.string().url(), ...sessionArg }),
    handler: async (a) => {
      const metaTool = extractTools.find((t) => t.name === "extract_meta")!;
      const res = await metaTool.handler(a);
      const parsed = JSON.parse(res.content[0].type === "text" ? res.content[0].text : "{}");
      const og = parsed.og ?? {};
      const tw = parsed.twitter ?? {};
      return ok({
        url: a.url,
        title: og.title ?? tw.title ?? parsed.title,
        description: og.description ?? tw.description,
        image: og.image ?? tw.image,
        siteName: og.site_name,
        type: og.type,
        canonical: parsed.canonical,
      });
    },
  },
  {
    name: "extract_wikipedia_page",
    description: "Fetch a full Wikipedia page's intro + sections list, plain text.",
    schema: z.object({ title: z.string(), lang: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const lang = a.lang ?? "en";
      const url = `https://${lang}.wikipedia.org/w/api.php?action=parse&page=${encodeURIComponent(a.title)}&prop=text|sections&format=json&origin=*`;
      const r = await s.context.request.fetch(url, { ignoreHTTPSErrors: true });
      try {
        const j = JSON.parse(await r.text());
        if (!j.parse) return err(j.error?.info ?? "no page");
        const sections = (j.parse.sections ?? []).map((s: any) => ({ line: s.line, number: s.number, level: s.level }));
        const text = stripTags(j.parse.text?.["*"] ?? "").slice(0, 30000);
        return ok({ title: j.parse.title, sections, text });
      } catch { return err("parse failed"); }
    },
  },
];
