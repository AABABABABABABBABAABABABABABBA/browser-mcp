import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

async function hit(session: ReturnType<typeof hub.getSession>, template: {
  url: string; method: "GET" | "POST" | "PUT"; headers?: Record<string, string>; body?: string;
}, token: string) {
  const url = template.url.replace(/\{username\}/g, encodeURIComponent(token));
  const body = template.body?.replace(/\{username\}/g, token);
  const t0 = Date.now();
  try {
    const r = await session.context.request.fetch(url, {
      method: template.method, headers: template.headers ?? {}, data: body,
      ignoreHTTPSErrors: true, maxRedirects: 0,
    });
    const text = (await r.text().catch(() => "")).slice(0, 100000);
    return { ok: true, status: r.status(), size: text.length, text, location: r.headers()["location"] ?? null, ms: Date.now() - t0 };
  } catch (e: any) {
    return { ok: false, error: e?.message ?? String(e), ms: Date.now() - t0 };
  }
}

const RANDOM_UNUSED_SEEDS = [
  () => "zxq_" + Math.random().toString(36).slice(2, 14),
  () => "unlikely_" + Math.random().toString(36).slice(2, 10) + "_user",
  () => "nope" + Math.random().toString(36).slice(2, 12),
];

export const usernameTools: ToolDef[] = [
  {
    name: "username_profile_endpoint",
    description: "Fingerprint what 'available' vs 'taken' looks like on a service. Give it a URL template with {username}, plus one known-taken name (optional — tool will try common ones). It probes with the taken name and 3 random unused ones, diffs status/length/body, and returns the signature later used by username_check_batch. Works for any site: HTML pages, JSON APIs, 404 redirects, inline validation endpoints.",
    schema: z.object({
      urlTemplate: z.string().describe("e.g. 'https://guns.lol/{username}' or 'https://site.com/api/check?u={username}'"),
      method: z.enum(["GET", "POST", "PUT"]).optional(),
      headers: z.record(z.string()).optional(),
      bodyTemplate: z.string().optional().describe("for POST, {username} is substituted inside this"),
      knownTaken: z.array(z.string()).optional().describe("usernames known to exist; defaults to ['admin','test','user']"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const template = { url: a.urlTemplate, method: a.method ?? "GET", headers: a.headers, body: a.bodyTemplate };
      const taken = a.knownTaken ?? ["admin", "test", "user"];
      const taken_probes = await Promise.all(taken.map((u: string) => hit(s, template, u).then((r: any) => ({ username: u, ...r }))));
      const unused_probes = await Promise.all(RANDOM_UNUSED_SEEDS.map((f: () => string) => { const u = f(); return hit(s, template, u).then((r: any) => ({ username: u, ...r })); }));

      // Build signature. The classifier is: {takenCode, availableCode, bodyMarker}
      const takenOK = taken_probes.filter((p) => p.ok) as any[];
      const unusedOK = unused_probes.filter((p) => p.ok) as any[];
      if (!takenOK.length || !unusedOK.length) return err("could not profile endpoint; some probes failed");

      // Majority status for each side
      const majority = (arr: any[]) => { const m = new Map<number, number>(); for (const x of arr) m.set(x.status, (m.get(x.status) ?? 0) + 1); return [...m.entries()].sort((a, b) => b[1] - a[1])[0][0]; };
      const takenStatus = majority(takenOK);
      const availStatus = majority(unusedOK);

      // Any marker string that appears in all unused and in no taken?
      const findMarker = (haves: string[], haveNots: string[]): string | null => {
        if (!haves.length) return null;
        const candidates = ["not found", "available", "doesn't exist", "does not exist", "no user", "404", "User not found", '"available":true', '"exists":false', '"found":false'];
        for (const c of candidates) {
          if (haves.every((t) => t.toLowerCase().includes(c.toLowerCase())) && haveNots.every((t) => !t.toLowerCase().includes(c.toLowerCase()))) return c;
        }
        return null;
      };
      const availableMarker = findMarker(unusedOK.map((p) => p.text), takenOK.map((p) => p.text));
      const takenMarker = findMarker(takenOK.map((p) => p.text), unusedOK.map((p) => p.text));

      const sizesTaken = takenOK.map((p) => p.size);
      const sizesAvail = unusedOK.map((p) => p.size);
      const avg = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
      const sizeSplit = Math.abs(avg(sizesTaken) - avg(sizesAvail)) > Math.max(50, 0.1 * Math.max(avg(sizesTaken), avg(sizesAvail)));

      const signature = {
        availableStatus: takenStatus === availStatus ? null : availStatus,
        takenStatus: takenStatus === availStatus ? null : takenStatus,
        availableMarker, takenMarker,
        sizeSplit, avgTakenSize: avg(sizesTaken), avgAvailSize: avg(sizesAvail),
        locationChange: takenOK[0].location !== unusedOK[0].location,
      };

      // Confidence
      const strong = (signature.availableStatus !== null) || !!availableMarker || !!takenMarker || sizeSplit;
      return ok({ template, signature, confidence: strong ? "high" : "low", probes: { taken: taken_probes, unused: unused_probes } });
    },
  },
  {
    name: "username_check_batch",
    description: "Batch-check a list of usernames against a URL template, using a signature produced by username_profile_endpoint (or your own). Returns which are AVAILABLE, which are TAKEN, which were AMBIGUOUS. Concurrent, polite rate-limiting built in.",
    schema: z.object({
      urlTemplate: z.string(),
      method: z.enum(["GET", "POST", "PUT"]).optional(),
      headers: z.record(z.string()).optional(),
      bodyTemplate: z.string().optional(),
      usernames: z.array(z.string()).min(1),
      signature: z.object({
        availableStatus: z.number().nullable().optional(),
        takenStatus: z.number().nullable().optional(),
        availableMarker: z.string().nullable().optional(),
        takenMarker: z.string().nullable().optional(),
        sizeSplit: z.boolean().optional(),
        avgTakenSize: z.number().optional(),
        avgAvailSize: z.number().optional(),
      }),
      concurrency: z.number().int().min(1).max(20).optional(),
      delayMs: z.number().int().min(0).max(5000).optional().describe("between-request delay per worker; default 100"),
      stopAfterAvailable: z.number().int().positive().optional().describe("stop early once this many available ones are found"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const template = { url: a.urlTemplate, method: a.method ?? "GET" as const, headers: a.headers, body: a.bodyTemplate };
      const sig = a.signature;
      const concurrency = Math.min(a.concurrency ?? 5, a.usernames.length);
      const delay = a.delayMs ?? 100;
      const limit = a.stopAfterAvailable ?? Infinity;
      let i = 0;
      const results: Array<{ username: string; status: "available" | "taken" | "ambiguous" | "error"; code?: number; reason: string }> = [];
      let availableCount = 0;
      let stop = false;

      const classify = (r: any): { verdict: "available" | "taken" | "ambiguous" | "error"; reason: string } => {
        if (!r.ok) return { verdict: "error", reason: r.error };
        const t = (r.text as string).toLowerCase();
        if (sig.availableMarker && t.includes(sig.availableMarker.toLowerCase())) return { verdict: "available", reason: `marker:${sig.availableMarker}` };
        if (sig.takenMarker && t.includes(sig.takenMarker.toLowerCase())) return { verdict: "taken", reason: `marker:${sig.takenMarker}` };
        if (sig.availableStatus != null && r.status === sig.availableStatus) return { verdict: "available", reason: `status=${r.status}` };
        if (sig.takenStatus != null && r.status === sig.takenStatus) return { verdict: "taken", reason: `status=${r.status}` };
        if (sig.sizeSplit && sig.avgTakenSize !== undefined && sig.avgAvailSize !== undefined) {
          const dTaken = Math.abs(r.size - sig.avgTakenSize);
          const dAvail = Math.abs(r.size - sig.avgAvailSize);
          if (dTaken > dAvail * 2) return { verdict: "available", reason: `size≈avail` };
          if (dAvail > dTaken * 2) return { verdict: "taken", reason: `size≈taken` };
        }
        return { verdict: "ambiguous", reason: `status=${r.status} size=${r.size}` };
      };

      const worker = async () => {
        while (!stop && i < a.usernames.length) {
          const u = a.usernames[i++];
          const r = await hit(s, template, u);
          const c = classify(r);
          results.push({ username: u, status: c.verdict, code: r.ok ? r.status : undefined, reason: c.reason });
          if (c.verdict === "available") { availableCount++; if (availableCount >= limit) stop = true; }
          if (delay) await new Promise((res) => setTimeout(res, delay));
        }
      };
      await Promise.all(Array.from({ length: concurrency }, () => worker()));
      results.sort((a, b) => a.username.localeCompare(b.username));
      return ok({
        total: a.usernames.length,
        checked: results.length,
        available: results.filter((r) => r.status === "available").map((r) => r.username),
        taken: results.filter((r) => r.status === "taken").length,
        ambiguous: results.filter((r) => r.status === "ambiguous").map((r) => r.username),
        errors: results.filter((r) => r.status === "error").length,
        results,
      });
    },
  },
  {
    name: "username_wordlist",
    description: "Generate username wordlists. Shapes: short (3-4 chars from a..z0..9), common (popular names), leet (variations of a base), numeric (base + N digits), mixed.",
    schema: z.object({
      shape: z.enum(["short", "common", "leet", "numeric", "mixed"]),
      length: z.number().int().positive().optional(),
      base: z.string().optional().describe("for leet/numeric variants"),
      limit: z.number().int().min(1).max(50000).optional(),
    }),
    handler: async (a) => {
      const limit = a.limit ?? 500;
      const out: string[] = [];
      if (a.shape === "short") {
        const len = Math.max(2, Math.min(4, a.length ?? 3));
        const chars = "abcdefghijklmnopqrstuvwxyz0123456789_";
        const rec = (prefix: string, depth: number) => {
          if (out.length >= limit) return;
          if (depth === 0) { out.push(prefix); return; }
          for (const c of chars) { if (out.length >= limit) return; rec(prefix + c, depth - 1); }
        };
        rec("", len);
      } else if (a.shape === "common") {
        const names = ["admin","root","test","demo","user","guest","alex","sam","chris","david","mike","john","mary","jen","emma","olivia","ava","noah","liam","elijah","mason","leo","max","nick","owen","dylan","sean","ryan","jay","kai","kyle","ethan","ava","maya","lily","mia","ella","aria","zoe","nova","hero","ghost","shadow","wolf","viper","night","dark","prime","neo","alpha","beta","omega","void","zero","one","boss","king","queen","ace","pro","mvp","elite","legend","god","demon","angel","ninja","samurai","dragon","phoenix","hunter","gamer","player"];
        for (const n of names) { if (out.length >= limit) break; out.push(n); }
      } else if (a.shape === "numeric") {
        if (!a.base) return err("base required");
        for (let i = 0; i < limit; i++) out.push(`${a.base}${i}`);
      } else if (a.shape === "leet") {
        if (!a.base) return err("base required");
        const subs: Record<string, string[]> = { a: ["a","4","@"], e: ["e","3"], i: ["i","1","!"], o: ["o","0"], s: ["s","5","$"], t: ["t","7"], l: ["l","1"], g: ["g","9"] };
        const gen = (acc: string, idx: number) => {
          if (out.length >= limit) return;
          if (idx === a.base!.length) { out.push(acc); return; }
          const c = a.base![idx].toLowerCase();
          const options = subs[c] ?? [c];
          for (const o of options) gen(acc + o, idx + 1);
        };
        gen("", 0);
      } else if (a.shape === "mixed") {
        if (!a.base) return err("base required");
        const suffixes = ["", "_", "x", "1", "01", "99", "007", "yt", "tv", "hd", "pro", "og", "gg"];
        for (const s of suffixes) { if (out.length >= limit) break; out.push(a.base + s); }
        for (let n = 0; n < 100 && out.length < limit; n++) out.push(`${a.base}${n}`);
      }
      return ok({ count: out.length, usernames: out });
    },
  },
];
