import { z } from "zod";
import { ToolDef, ok, err } from "../types.js";

const STOPWORDS = new Set(("the of and to a in is you that it he was for on are as with his they i at be this have from or one had by word but not what all were we when your can said there use an each which she do how their if will up other about out many then them these so some her would make like him into time has look two more write go see number no way could people my than first water been call who oil its now find long down day did get come made may part a an and the is are was were be been being have has had do does did will would could should may might must can shall of to in on at by for with from into through during before after above below between among about against toward within without under upon since until unless once").split(/\s+/));

const POS = new Set(["good","great","excellent","love","happy","best","wonderful","amazing","awesome","fantastic","delighted","superb","brilliant","perfect","win","wins","loved","likes","liking","nice","beautiful","positive","gain","gains","benefit","benefits","succeed","success","successful"]);
const NEG = new Set(["bad","worst","hate","sad","angry","terrible","awful","horrible","failed","fail","loss","losses","losing","problem","problems","broken","crash","error","errors","sucks","worse","negative","risk","risks","danger","wrong","wrongly"]);

function sentences(text: string): string[] {
  return text.replace(/\s+/g, " ").split(/(?<=[.!?])\s+(?=[A-Z0-9"])/).map((s) => s.trim()).filter(Boolean);
}

function wordsOf(text: string): string[] { return text.toLowerCase().match(/[a-z][a-z'-]+/g) ?? []; }

export const aiTextTools: ToolDef[] = [
  {
    name: "ai_summarize",
    description: "Extractive summarization — picks the top-N most 'important' sentences by frequency of non-stopword terms. No external model needed.",
    schema: z.object({ text: z.string().min(50), sentences: z.number().int().positive().optional() }),
    handler: async (a) => {
      const sents = sentences(a.text);
      if (sents.length <= 2) return ok({ summary: a.text });
      const freq: Record<string, number> = {};
      for (const w of wordsOf(a.text)) if (!STOPWORDS.has(w)) freq[w] = (freq[w] ?? 0) + 1;
      const scored = sents.map((s, i) => ({ i, s, score: wordsOf(s).filter((w) => !STOPWORDS.has(w)).reduce((a, w) => a + (freq[w] ?? 0), 0) / Math.max(1, wordsOf(s).length) }));
      const top = scored.slice().sort((a, b) => b.score - a.score).slice(0, a.sentences ?? 3).sort((a, b) => a.i - b.i);
      return ok({ summary: top.map((t) => t.s).join(" "), picked: top.length, outOf: sents.length });
    },
  },
  {
    name: "ai_keywords",
    description: "Keyword extraction via TF with stopword filtering. Fast + no network.",
    schema: z.object({ text: z.string(), limit: z.number().int().positive().optional() }),
    handler: async (a) => {
      const freq: Record<string, number> = {};
      for (const w of wordsOf(a.text)) if (w.length > 2 && !STOPWORDS.has(w)) freq[w] = (freq[w] ?? 0) + 1;
      const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, a.limit ?? 20);
      return ok({ keywords: sorted.map(([word, count]) => ({ word, count })) });
    },
  },
  {
    name: "ai_sentences",
    description: "Split text into sentences (handles abbreviations okay-ish).",
    schema: z.object({ text: z.string() }),
    handler: async (a) => ok({ sentences: sentences(a.text) }),
  },
  {
    name: "ai_reading_time",
    description: "Estimated reading time in minutes (words / 230).",
    schema: z.object({ text: z.string(), wpm: z.number().int().positive().optional() }),
    handler: async (a) => {
      const words = (a.text.match(/\S+/g) ?? []).length;
      return ok({ words, minutes: Math.max(1, Math.round(words / (a.wpm ?? 230))) });
    },
  },
  {
    name: "ai_readability_flesch",
    description: "Flesch Reading-Ease score (90-100 = very easy, 0-30 = very confusing).",
    schema: z.object({ text: z.string() }),
    handler: async (a) => {
      const sents = sentences(a.text);
      const words = wordsOf(a.text);
      if (!sents.length || !words.length) return ok({ score: null });
      const syll = (w: string) => Math.max(1, (w.match(/[aeiouy]+/g) ?? []).length);
      const totalSyll = words.reduce((a, w) => a + syll(w), 0);
      const score = 206.835 - 1.015 * (words.length / sents.length) - 84.6 * (totalSyll / words.length);
      let grade: string;
      if (score >= 90) grade = "very easy (5th grade)";
      else if (score >= 80) grade = "easy (6th grade)";
      else if (score >= 70) grade = "fairly easy (7th grade)";
      else if (score >= 60) grade = "standard (8-9th)";
      else if (score >= 50) grade = "fairly difficult (10-12th)";
      else if (score >= 30) grade = "difficult (college)";
      else grade = "very confusing (graduate)";
      return ok({ score: Math.round(score * 10) / 10, grade, words: words.length, sentences: sents.length, syllables: totalSyll });
    },
  },
  {
    name: "ai_sentiment",
    description: "Rough lexicon-based sentiment score — positive/negative word ratio.",
    schema: z.object({ text: z.string() }),
    handler: async (a) => {
      const words = wordsOf(a.text);
      let pos = 0, neg = 0;
      for (const w of words) { if (POS.has(w)) pos++; if (NEG.has(w)) neg++; }
      const score = (pos - neg) / Math.max(1, words.length);
      let label = "neutral";
      if (score > 0.01) label = "positive";
      else if (score < -0.01) label = "negative";
      return ok({ label, score: Math.round(score * 1000) / 1000, positiveWords: pos, negativeWords: neg });
    },
  },
  {
    name: "ai_detect_language",
    description: "Heuristic language detection by character/stopword patterns. Handles major European languages + Chinese/Japanese/Korean/Arabic/Hebrew/Russian scripts.",
    schema: z.object({ text: z.string() }),
    handler: async (a) => {
      const t = a.text.slice(0, 5000);
      if (/[一-鿿]/.test(t)) return ok({ language: "zh", script: "Han" });
      if (/[぀-ゟ゠-ヿ]/.test(t)) return ok({ language: "ja", script: "Kana" });
      if (/[가-힯]/.test(t)) return ok({ language: "ko", script: "Hangul" });
      if (/[؀-ۿ]/.test(t)) return ok({ language: "ar", script: "Arabic" });
      if (/[֐-׿]/.test(t)) return ok({ language: "he", script: "Hebrew" });
      if (/[Ѐ-ӿ]/.test(t)) return ok({ language: "ru", script: "Cyrillic" });
      if (/[฀-๿]/.test(t)) return ok({ language: "th", script: "Thai" });
      const words = wordsOf(t);
      const scores: Record<string, number> = {};
      const markers: Record<string, string[]> = {
        en: ["the", "and", "that", "with", "this", "have"],
        es: ["el", "los", "las", "pero", "para", "está", "con", "una"],
        fr: ["le", "les", "des", "pour", "avec", "dans", "mais", "sont"],
        de: ["der", "die", "das", "und", "ist", "nicht", "mit", "sind"],
        pt: ["não", "para", "com", "mas", "está", "uma", "você"],
        it: ["che", "con", "per", "una", "sono", "nella", "della", "questo"],
        nl: ["het", "een", "voor", "zijn", "niet", "maar", "met", "deze"],
      };
      for (const [lang, ws] of Object.entries(markers)) scores[lang] = words.filter((w) => ws.includes(w)).length;
      const best = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];
      return ok({ language: best[1] > 0 ? best[0] : "unknown", confidence: best[1] / Math.max(1, words.length), scores });
    },
  },
  {
    name: "ai_outline",
    description: "Build an outline from Markdown or HTML — list of headings (level, text).",
    schema: z.object({ text: z.string(), format: z.enum(["markdown", "html"]).optional() }),
    handler: async (a) => {
      const fmt = a.format ?? (a.text.includes("<h") ? "html" : "markdown");
      const outline: Array<{ level: number; text: string }> = [];
      if (fmt === "markdown") {
        for (const m of a.text.matchAll(/^(#{1,6})\s+(.+)$/gm)) outline.push({ level: m[1].length, text: m[2].trim() });
      } else {
        for (const m of a.text.matchAll(/<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi)) outline.push({ level: +m[1], text: m[2].replace(/<[^>]+>/g, "").trim() });
      }
      return ok({ outline });
    },
  },
  {
    name: "ai_word_freq",
    description: "Full word-frequency table of a text (lowercased, stopword-aware).",
    schema: z.object({ text: z.string(), includeStopwords: z.boolean().optional(), limit: z.number().int().positive().optional() }),
    handler: async (a) => {
      const freq: Record<string, number> = {};
      for (const w of wordsOf(a.text)) if (a.includeStopwords || !STOPWORDS.has(w)) freq[w] = (freq[w] ?? 0) + 1;
      const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, a.limit ?? 200);
      return ok({ unique: Object.keys(freq).length, top: sorted });
    },
  },
  {
    name: "ai_ngrams",
    description: "Extract most-common n-grams of a given size.",
    schema: z.object({ text: z.string(), n: z.number().int().min(2).max(5), limit: z.number().int().positive().optional() }),
    handler: async (a) => {
      const words = wordsOf(a.text);
      const freq: Record<string, number> = {};
      for (let i = 0; i <= words.length - a.n; i++) {
        const chunk = words.slice(i, i + a.n);
        if (chunk.some((w) => STOPWORDS.has(w))) continue;
        const key = chunk.join(" ");
        freq[key] = (freq[key] ?? 0) + 1;
      }
      return ok({ ngrams: Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, a.limit ?? 30) });
    },
  },
  {
    name: "ai_entities_simple",
    description: "Crude named-entity extraction: capitalized sequences (names/places/orgs) + emails + URLs + dates.",
    schema: z.object({ text: z.string() }),
    handler: async (a) => {
      const names = Array.from(new Set(Array.from(a.text.matchAll(/\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b/g)).map((m: any) => m[1])));
      const emails = Array.from(new Set(Array.from(a.text.matchAll(/[\w.+-]+@[\w-]+\.[\w.-]{2,24}/g)).map((m: any) => m[0])));
      const urls = Array.from(new Set(Array.from(a.text.matchAll(/https?:\/\/[^\s"'<>()]+/g)).map((m: any) => m[0])));
      const dates = Array.from(new Set(Array.from(a.text.matchAll(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2}(?:,\s*\d{4})?|\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4}\b/g)).map((m: any) => m[0])));
      return ok({ names, emails, urls, dates });
    },
  },
  {
    name: "ai_diff",
    description: "Line-diff two strings (add / remove / unchanged).",
    schema: z.object({ a: z.string(), b: z.string() }),
    handler: async (a) => {
      const A = a.a.split(/\r?\n/), B = a.b.split(/\r?\n/);
      // Hirschberg-ish simple LCS diff
      const dp: number[][] = Array.from({ length: A.length + 1 }, () => Array(B.length + 1).fill(0));
      for (let i = 1; i <= A.length; i++) for (let j = 1; j <= B.length; j++) dp[i][j] = A[i-1] === B[j-1] ? dp[i-1][j-1] + 1 : Math.max(dp[i-1][j], dp[i][j-1]);
      const out: any[] = []; let i = A.length, j = B.length;
      while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && A[i-1] === B[j-1]) { out.unshift({ op: "equal", line: A[i-1] }); i--; j--; }
        else if (j > 0 && (i === 0 || dp[i][j-1] >= dp[i-1][j])) { out.unshift({ op: "add", line: B[j-1] }); j--; }
        else { out.unshift({ op: "remove", line: A[i-1] }); i--; }
      }
      return ok({ diff: out, adds: out.filter((o) => o.op === "add").length, removes: out.filter((o) => o.op === "remove").length });
    },
  },
  {
    name: "ai_compare_urls",
    description: "Fetch 2+ URLs, extract their articles, compare word count / reading time / top keywords side-by-side.",
    schema: z.object({ urls: z.array(z.string().url()).min(2).max(5), sessionId: z.string().optional() }),
    handler: async (a) => {
      const { extractTools } = await import("./extract.js");
      const ext = extractTools.find((t) => t.name === "extract_article")!;
      const kwTool = aiTextTools.find((t) => t.name === "ai_keywords")!;
      const rtTool = aiTextTools.find((t) => t.name === "ai_reading_time")!;
      const items: any[] = [];
      for (const url of a.urls) {
        const art = JSON.parse(((await ext.handler({ url, sessionId: a.sessionId })).content[0] as any).text);
        const kws = JSON.parse(((await kwTool.handler({ text: art.text ?? "", limit: 10 })).content[0] as any).text);
        const rt = JSON.parse(((await rtTool.handler({ text: art.text ?? "" })).content[0] as any).text);
        items.push({ url, title: art.title, textLength: art.text?.length ?? 0, readingMinutes: rt.minutes, words: rt.words, keywords: kws.keywords.map((k: any) => k.word) });
      }
      return ok(items);
    },
  },
];
