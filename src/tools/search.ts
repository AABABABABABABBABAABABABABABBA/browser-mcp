import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

async function get(session: ReturnType<typeof hub.getSession>, url: string, headers: Record<string, string> = {}) {
  const r = await session.context.request.fetch(url, {
    ignoreHTTPSErrors: true, timeout: 20000,
    headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", ...headers },
  } as any);
  const text = await r.text().catch(() => "");
  return { status: r.status(), text, headers: r.headers() };
}

function stripHtml(s: string): string { return s.replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").trim(); }

export const searchTools: ToolDef[] = [
  {
    name: "search_web",
    description: "Web search via DuckDuckGo HTML endpoint. Returns ranked results with title, URL, snippet. No API key needed.",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), region: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(a.q)}${a.region ? `&kl=${a.region}` : ""}`;
      const { text, status } = await get(s, url);
      if (status >= 400) return err(`DDG returned ${status}`);
      const results: any[] = [];
      const re = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) && results.length < (a.limit ?? 20)) {
        let href = m[1];
        if (href.startsWith("//")) href = "https:" + href;
        try { const u = new URL(href); const uddg = u.searchParams.get("uddg"); if (uddg) href = decodeURIComponent(uddg); } catch {}
        results.push({ title: stripHtml(m[2]), url: href, snippet: stripHtml(m[3]) });
      }
      return ok({ query: a.q, count: results.length, results });
    },
  },
  {
    name: "search_bing",
    description: "Bing web search via HTML. Returns ranked results.",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const url = `https://www.bing.com/search?q=${encodeURIComponent(a.q)}`;
      const { text, status } = await get(s, url);
      if (status >= 400) return err(`Bing returned ${status}`);
      const results: any[] = [];
      const re = /<li class="b_algo"[^>]*>[\s\S]*?<h2>\s*<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?<p[^>]*>([\s\S]*?)<\/p>/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) && results.length < (a.limit ?? 15)) {
        results.push({ title: stripHtml(m[2]), url: m[1], snippet: stripHtml(m[3]) });
      }
      return ok({ query: a.q, count: results.length, results });
    },
  },
  {
    name: "search_news",
    description: "News search via Google News RSS feed (no key).",
    schema: z.object({ q: z.string(), lang: z.string().optional(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const url = `https://news.google.com/rss/search?q=${encodeURIComponent(a.q)}&hl=${a.lang ?? "en-US"}&gl=US&ceid=US:en`;
      const { text, status } = await get(s, url);
      if (status >= 400) return err(`Google News returned ${status}`);
      const items: any[] = [];
      const re = /<item>([\s\S]*?)<\/item>/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) && items.length < (a.limit ?? 15)) {
        const block = m[1];
        const title = /<title>([\s\S]*?)<\/title>/.exec(block)?.[1] ?? "";
        const link = /<link>([\s\S]*?)<\/link>/.exec(block)?.[1] ?? "";
        const pub = /<pubDate>([\s\S]*?)<\/pubDate>/.exec(block)?.[1] ?? "";
        const src = /<source[^>]*>([\s\S]*?)<\/source>/.exec(block)?.[1] ?? "";
        items.push({ title: stripHtml(title), url: link.trim(), source: stripHtml(src), published: pub.trim() });
      }
      return ok({ query: a.q, count: items.length, items });
    },
  },
  {
    name: "search_images",
    description: "Image search via DuckDuckGo. Returns image URL, source URL, thumbnail, dimensions.",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      // DDG needs a token first
      const landing = await get(s, `https://duckduckgo.com/?q=${encodeURIComponent(a.q)}&iax=images&ia=images`);
      const vqd = /vqd=['"]([\w-]+)['"]/.exec(landing.text)?.[1];
      if (!vqd) return err("couldn't get DDG vqd token");
      const url = `https://duckduckgo.com/i.js?o=json&q=${encodeURIComponent(a.q)}&vqd=${vqd}&f=,,,,,`;
      const { text } = await get(s, url);
      try {
        const j = JSON.parse(text);
        return ok({ query: a.q, count: j.results?.length ?? 0, images: (j.results ?? []).slice(0, a.limit ?? 30).map((r: any) => ({ title: r.title, image: r.image, thumbnail: r.thumbnail, source: r.url, width: r.width, height: r.height })) });
      } catch { return err("couldn't parse DDG image results"); }
    },
  },
  {
    name: "search_github_code",
    description: "GitHub code search via public search API (unauthenticated, limited to 60 req/hr).",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const { text, status } = await get(s, `https://api.github.com/search/code?q=${encodeURIComponent(a.q)}&per_page=${a.limit ?? 10}`, { "Accept": "application/vnd.github+json" });
      if (status >= 400) return err(`GitHub returned ${status}`);
      try { const j = JSON.parse(text); return ok({ total: j.total_count, items: (j.items ?? []).map((i: any) => ({ repo: i.repository?.full_name, path: i.path, url: i.html_url, score: i.score })) }); }
      catch { return err("parse failed"); }
    },
  },
  {
    name: "search_github_repos",
    description: "GitHub repo search.",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const { text, status } = await get(s, `https://api.github.com/search/repositories?q=${encodeURIComponent(a.q)}&per_page=${a.limit ?? 15}`);
      if (status >= 400) return err(`${status}`);
      try { const j = JSON.parse(text); return ok({ total: j.total_count, items: (j.items ?? []).map((r: any) => ({ repo: r.full_name, stars: r.stargazers_count, lang: r.language, desc: r.description, url: r.html_url, pushed: r.pushed_at })) }); }
      catch { return err("parse failed"); }
    },
  },
  {
    name: "search_reddit",
    description: "Reddit search via the public .json endpoint.",
    schema: z.object({ q: z.string(), subreddit: z.string().optional(), sort: z.enum(["relevance", "hot", "top", "new"]).optional(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const path = a.subreddit ? `/r/${a.subreddit}/search` : `/search`;
      const url = `https://www.reddit.com${path}.json?q=${encodeURIComponent(a.q)}&sort=${a.sort ?? "relevance"}&limit=${a.limit ?? 20}${a.subreddit ? "&restrict_sr=on" : ""}`;
      const { text, status } = await get(s, url, { "User-Agent": "browser-mcp/0.1" });
      if (status >= 400) return err(`Reddit ${status}`);
      try {
        const j = JSON.parse(text);
        const posts = (j.data?.children ?? []).map((c: any) => ({ title: c.data.title, subreddit: c.data.subreddit, author: c.data.author, score: c.data.score, comments: c.data.num_comments, url: `https://reddit.com${c.data.permalink}`, link: c.data.url_overridden_by_dest ?? c.data.url, created: c.data.created_utc, selftext: (c.data.selftext ?? "").slice(0, 400) }));
        return ok({ query: a.q, count: posts.length, posts });
      } catch { return err("parse failed"); }
    },
  },
  {
    name: "search_wikipedia",
    description: "Wikipedia search + summary via the public API.",
    schema: z.object({ q: z.string(), lang: z.string().optional(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const lang = a.lang ?? "en";
      const url = `https://${lang}.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(a.q)}&srlimit=${a.limit ?? 10}&format=json&origin=*`;
      const { text, status } = await get(s, url);
      if (status >= 400) return err(`${status}`);
      try { const j = JSON.parse(text); return ok({ results: (j.query?.search ?? []).map((r: any) => ({ title: r.title, snippet: stripHtml(r.snippet), size: r.size, wordcount: r.wordcount, url: `https://${lang}.wikipedia.org/wiki/${encodeURIComponent(r.title.replace(/ /g, "_"))}` })) }); }
      catch { return err("parse failed"); }
    },
  },
  {
    name: "wikipedia_summary",
    description: "Fetch the lead paragraph summary of a Wikipedia page.",
    schema: z.object({ title: z.string(), lang: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const lang = a.lang ?? "en";
      const url = `https://${lang}.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(a.title.replace(/ /g, "_"))}`;
      const { text, status } = await get(s, url);
      if (status >= 400) return err(`${status}`);
      try { const j = JSON.parse(text); return ok({ title: j.title, description: j.description, extract: j.extract, thumbnail: j.thumbnail?.source, url: j.content_urls?.desktop?.page }); }
      catch { return err("parse failed"); }
    },
  },
  {
    name: "search_arxiv",
    description: "Search arXiv (preprints) via its public query API.",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const url = `http://export.arxiv.org/api/query?search_query=all:${encodeURIComponent(a.q)}&max_results=${a.limit ?? 10}`;
      const { text, status } = await get(s, url);
      if (status >= 400) return err(`${status}`);
      const items: any[] = [];
      const re = /<entry>([\s\S]*?)<\/entry>/g; let m: RegExpExecArray | null;
      while ((m = re.exec(text))) {
        const b = m[1];
        items.push({
          id: /<id>([\s\S]*?)<\/id>/.exec(b)?.[1]?.trim(),
          title: stripHtml(/<title>([\s\S]*?)<\/title>/.exec(b)?.[1] ?? ""),
          summary: stripHtml(/<summary>([\s\S]*?)<\/summary>/.exec(b)?.[1] ?? "").slice(0, 500),
          published: /<published>([\s\S]*?)<\/published>/.exec(b)?.[1],
          authors: Array.from(b.matchAll(/<name>([\s\S]*?)<\/name>/g)).map((x) => x[1].trim()),
        });
      }
      return ok({ count: items.length, items });
    },
  },
  {
    name: "search_stackoverflow",
    description: "StackOverflow search via the StackExchange API.",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), tag: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const params = `order=desc&sort=relevance&q=${encodeURIComponent(a.q)}&site=stackoverflow&pagesize=${a.limit ?? 15}${a.tag ? `&tagged=${a.tag}` : ""}`;
      const { text, status } = await get(s, `https://api.stackexchange.com/2.3/search/advanced?${params}`);
      if (status >= 400) return err(`${status}`);
      try { const j = JSON.parse(text); return ok({ items: (j.items ?? []).map((i: any) => ({ title: i.title, score: i.score, answers: i.answer_count, isAnswered: i.is_answered, tags: i.tags, link: i.link, created: i.creation_date })) }); }
      catch { return err("parse failed"); }
    },
  },
  {
    name: "search_hackernews",
    description: "Hacker News search via Algolia.",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const { text, status } = await get(s, `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(a.q)}&hitsPerPage=${a.limit ?? 20}`);
      if (status >= 400) return err(`${status}`);
      try { const j = JSON.parse(text); return ok({ hits: (j.hits ?? []).map((h: any) => ({ title: h.title ?? h.story_title, author: h.author, points: h.points, comments: h.num_comments, url: h.url ?? `https://news.ycombinator.com/item?id=${h.objectID}`, created: h.created_at })) }); }
      catch { return err("parse failed"); }
    },
  },
  {
    name: "search_youtube",
    description: "YouTube search via scraping the HTML search page. No API key.",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const { text, status } = await get(s, `https://www.youtube.com/results?search_query=${encodeURIComponent(a.q)}`);
      if (status >= 400) return err(`${status}`);
      const m = /var ytInitialData\s*=\s*(\{[\s\S]*?\});\s*<\/script>/.exec(text);
      if (!m) return err("couldn't find ytInitialData");
      try {
        const data = JSON.parse(m[1]);
        const items = data.contents?.twoColumnSearchResultsRenderer?.primaryContents?.sectionListRenderer?.contents?.[0]?.itemSectionRenderer?.contents ?? [];
        const videos = items.filter((i: any) => i.videoRenderer).map((i: any) => {
          const v = i.videoRenderer;
          return { title: v.title?.runs?.[0]?.text, videoId: v.videoId, url: `https://youtube.com/watch?v=${v.videoId}`, channel: v.ownerText?.runs?.[0]?.text, length: v.lengthText?.simpleText, views: v.viewCountText?.simpleText, published: v.publishedTimeText?.simpleText, thumbnail: v.thumbnail?.thumbnails?.[0]?.url };
        }).slice(0, a.limit ?? 15);
        return ok({ query: a.q, count: videos.length, videos });
      } catch (e: any) { return err(`parse failed: ${e.message}`); }
    },
  },
  {
    name: "search_with_citations",
    description: "Perplexity-style answer: run a web search, fetch the top N results, extract their main text, return a citation list so the model can synthesize a cited answer.",
    schema: z.object({
      q: z.string(),
      sources: z.number().int().min(1).max(10).optional().describe("how many top results to actually fetch (default 5)"),
      maxCharsPerSource: z.number().int().positive().optional(),
      engine: z.enum(["duckduckgo", "bing"]).optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const engine = a.engine ?? "duckduckgo";
      const searchResult = await (engine === "bing" ? searchTools.find((t) => t.name === "search_bing")!.handler({ q: a.q, limit: 10, sessionId: a.sessionId })
        : searchTools.find((t) => t.name === "search_web")!.handler({ q: a.q, limit: 10, sessionId: a.sessionId }));
      const sr = JSON.parse(searchResult.content[0].type === "text" ? searchResult.content[0].text : "{}");
      const top = (sr.results ?? []).slice(0, a.sources ?? 5);
      const cap = a.maxCharsPerSource ?? 3000;
      const extractor = (await import("./extract.js")).extractTools.find((t: any) => t.name === "extract_article");
      const citations: any[] = [];
      for (const r of top) {
        try {
          const art = extractor ? await extractor.handler({ url: r.url, sessionId: a.sessionId }) : null;
          const parsed = art ? JSON.parse(art.content[0].type === "text" ? art.content[0].text : "{}") : {};
          citations.push({ url: r.url, title: r.title, snippet: r.snippet, textLen: parsed.text?.length ?? 0, text: (parsed.text ?? r.snippet).slice(0, cap) });
        } catch { citations.push({ url: r.url, title: r.title, snippet: r.snippet, text: r.snippet, error: "fetch failed" }); }
      }
      return ok({ query: a.q, engine, citations, allResults: sr.results });
    },
  },
  {
    name: "search_followup",
    description: "Generate related follow-up questions from a search result set (simple rule-based: expands terms, probes 'why/how/when/vs')",
    schema: z.object({ q: z.string(), limit: z.number().int().positive().optional() }),
    handler: async (a) => {
      const terms = a.q.replace(/[?!.]/g, "").split(/\s+/).filter((t: string) => t.length > 2);
      const subj = terms.slice(0, 3).join(" ");
      const starters = ["What is", "How does", "Why does", "When should", "Where to use", "Who created", "Best alternatives to", "Downsides of", "History of", "Comparison between", "Latest news on"];
      const out = starters.map((s) => `${s} ${subj}?`);
      return ok({ followups: out.slice(0, a.limit ?? 8) });
    },
  },
];
