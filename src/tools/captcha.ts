import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

type Service = "2captcha" | "anticaptcha" | "capsolver";

async function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)); }

// ---- 2Captcha ----
async function solve2captcha(session: ReturnType<typeof hub.getSession>, apiKey: string, params: Record<string, string>, timeoutMs: number): Promise<{ token: string; id: string }> {
  const form = new URLSearchParams({ key: apiKey, json: "1", ...params });
  const sub = await session.context.request.fetch("https://2captcha.com/in.php", { method: "POST", data: form.toString(), headers: { "content-type": "application/x-www-form-urlencoded" }, ignoreHTTPSErrors: true } as any);
  const subJson = JSON.parse(await sub.text());
  if (subJson.status !== 1) throw new Error(`2captcha submit: ${subJson.request}`);
  const id = subJson.request as string;
  const deadline = Date.now() + timeoutMs;
  await sleep(10000); // 2captcha minimum wait
  while (Date.now() < deadline) {
    const r = await session.context.request.fetch(`https://2captcha.com/res.php?key=${apiKey}&action=get&id=${id}&json=1`, { ignoreHTTPSErrors: true });
    const j = JSON.parse(await r.text());
    if (j.status === 1) return { token: j.request, id };
    if (j.request && j.request !== "CAPCHA_NOT_READY") throw new Error(`2captcha: ${j.request}`);
    await sleep(5000);
  }
  throw new Error("2captcha timed out");
}

// ---- Anti-Captcha ----
async function solveAntiCaptcha(session: ReturnType<typeof hub.getSession>, apiKey: string, task: any, timeoutMs: number): Promise<{ token: string; id: number }> {
  const create = await session.context.request.fetch("https://api.anti-captcha.com/createTask", {
    method: "POST", data: JSON.stringify({ clientKey: apiKey, task }), headers: { "content-type": "application/json" }, ignoreHTTPSErrors: true,
  } as any);
  const createJson = JSON.parse(await create.text());
  if (createJson.errorId !== 0) throw new Error(`anticaptcha: ${createJson.errorDescription}`);
  const id = createJson.taskId;
  const deadline = Date.now() + timeoutMs;
  await sleep(8000);
  while (Date.now() < deadline) {
    const r = await session.context.request.fetch("https://api.anti-captcha.com/getTaskResult", { method: "POST", data: JSON.stringify({ clientKey: apiKey, taskId: id }), headers: { "content-type": "application/json" }, ignoreHTTPSErrors: true } as any);
    const j = JSON.parse(await r.text());
    if (j.errorId !== 0) throw new Error(`anticaptcha: ${j.errorDescription}`);
    if (j.status === "ready") {
      const tok = j.solution?.gRecaptchaResponse ?? j.solution?.token ?? j.solution?.text;
      if (!tok) throw new Error("no token in solution: " + JSON.stringify(j.solution));
      return { token: tok, id };
    }
    await sleep(4000);
  }
  throw new Error("anticaptcha timed out");
}

// ---- CapSolver ----
async function solveCapSolver(session: ReturnType<typeof hub.getSession>, apiKey: string, task: any, timeoutMs: number): Promise<{ token: string; id: string }> {
  const create = await session.context.request.fetch("https://api.capsolver.com/createTask", { method: "POST", data: JSON.stringify({ clientKey: apiKey, task }), headers: { "content-type": "application/json" }, ignoreHTTPSErrors: true } as any);
  const createJson = JSON.parse(await create.text());
  if (createJson.errorId) throw new Error(`capsolver: ${createJson.errorDescription}`);
  const id = createJson.taskId;
  const deadline = Date.now() + timeoutMs;
  await sleep(3000);
  while (Date.now() < deadline) {
    const r = await session.context.request.fetch("https://api.capsolver.com/getTaskResult", { method: "POST", data: JSON.stringify({ clientKey: apiKey, taskId: id }), headers: { "content-type": "application/json" }, ignoreHTTPSErrors: true } as any);
    const j = JSON.parse(await r.text());
    if (j.errorId) throw new Error(`capsolver: ${j.errorDescription}`);
    if (j.status === "ready") {
      const tok = j.solution?.gRecaptchaResponse ?? j.solution?.token ?? j.solution?.text;
      if (!tok) throw new Error("no token in solution: " + JSON.stringify(j.solution));
      return { token: tok, id };
    }
    await sleep(3000);
  }
  throw new Error("capsolver timed out");
}

async function solveToken(session: ReturnType<typeof hub.getSession>, service: Service, apiKey: string, kind: "recaptcha-v2" | "recaptcha-v3" | "hcaptcha" | "turnstile", sitekey: string, pageUrl: string, extra: any, timeoutMs: number): Promise<{ token: string }> {
  if (service === "2captcha") {
    const methodMap: any = { "recaptcha-v2": "userrecaptcha", "recaptcha-v3": "userrecaptcha", hcaptcha: "hcaptcha", turnstile: "turnstile" };
    const params: Record<string, string> = { method: methodMap[kind], pageurl: pageUrl };
    if (kind === "hcaptcha") params.sitekey = sitekey; else params.googlekey = sitekey;
    if (kind === "recaptcha-v3") { params.version = "v3"; if (extra?.action) params.action = extra.action; if (extra?.minScore) params.min_score = String(extra.minScore); }
    const r = await solve2captcha(session, apiKey, params, timeoutMs);
    return { token: r.token };
  }
  if (service === "anticaptcha") {
    const taskType: any = { "recaptcha-v2": "RecaptchaV2TaskProxyless", "recaptcha-v3": "RecaptchaV3TaskProxyless", hcaptcha: "HCaptchaTaskProxyless", turnstile: "TurnstileTaskProxyless" };
    const task: any = { type: taskType[kind], websiteURL: pageUrl, websiteKey: sitekey };
    if (kind === "recaptcha-v3") { task.pageAction = extra?.action ?? ""; if (extra?.minScore) task.minScore = extra.minScore; }
    const r = await solveAntiCaptcha(session, apiKey, task, timeoutMs);
    return { token: r.token };
  }
  if (service === "capsolver") {
    const taskType: any = { "recaptcha-v2": "ReCaptchaV2TaskProxyLess", "recaptcha-v3": "ReCaptchaV3TaskProxyLess", hcaptcha: "HCaptchaTaskProxyLess", turnstile: "AntiTurnstileTaskProxyLess" };
    const task: any = { type: taskType[kind], websiteURL: pageUrl, websiteKey: sitekey };
    if (kind === "recaptcha-v3") { task.pageAction = extra?.action ?? ""; if (extra?.minScore) task.minScore = extra.minScore; }
    const r = await solveCapSolver(session, apiKey, task, timeoutMs);
    return { token: r.token };
  }
  throw new Error(`unknown service: ${service}`);
}

export const captchaTools: ToolDef[] = [
  {
    name: "captcha_detect",
    description: "Detect every captcha widget on the current page — reCAPTCHA v2 (visible/invisible), reCAPTCHA v3, hCaptcha, Cloudflare Turnstile, Arkose/FunCaptcha, GeeTest, image captchas with adjacent inputs. Returns sitekey + widget metadata needed to solve.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const data = await s.page.evaluate(() => {
        const widgets: any[] = [];
        // reCAPTCHA v2 — ONLY .g-recaptcha, not generic [data-sitekey] (that double-counts other providers)
        for (const el of Array.from(document.querySelectorAll(".g-recaptcha"))) {
          const sk = el.getAttribute("data-sitekey");
          if (!sk) continue;
          widgets.push({
            kind: "recaptcha-v2",
            sitekey: sk,
            invisible: el.getAttribute("data-size") === "invisible",
            theme: el.getAttribute("data-theme") || null,
            callback: el.getAttribute("data-callback") || null,
            element: el.tagName.toLowerCase(),
            provider: "google",
          });
        }
        // reCAPTCHA iframes
        for (const f of Array.from(document.querySelectorAll('iframe[src*="recaptcha"]'))) {
          const src = (f as any).src;
          const m = /[?&]k=([^&]+)/.exec(src);
          if (m && !widgets.some((w) => w.sitekey === m[1])) widgets.push({ kind: "recaptcha-v2", sitekey: m[1], invisible: /\binvisible\b/.test(src), element: "iframe", provider: "google" });
        }
        // reCAPTCHA v3 (grecaptcha.execute)
        for (const s of Array.from(document.querySelectorAll('script[src*="recaptcha/api.js"]'))) {
          const src = (s as any).src;
          const m = /[?&]render=([^&]+)/.exec(src);
          if (m && m[1] !== "explicit") widgets.push({ kind: "recaptcha-v3", sitekey: m[1], element: "script", provider: "google" });
        }
        // hCaptcha
        for (const el of Array.from(document.querySelectorAll(".h-captcha"))) {
          const sk = el.getAttribute("data-sitekey");
          if (!sk) continue;
          widgets.push({ kind: "hcaptcha", sitekey: sk, element: el.tagName.toLowerCase(), provider: "hcaptcha" });
        }
        for (const f of Array.from(document.querySelectorAll('iframe[src*="hcaptcha.com"]'))) {
          const src = (f as any).src;
          const m = /[?&]sitekey=([^&]+)/.exec(src);
          if (m && !widgets.some((w) => w.sitekey === m[1])) widgets.push({ kind: "hcaptcha", sitekey: m[1], element: "iframe", provider: "hcaptcha" });
        }
        // Cloudflare Turnstile
        for (const el of Array.from(document.querySelectorAll(".cf-turnstile"))) {
          const sk = el.getAttribute("data-sitekey");
          if (!sk) continue;
          widgets.push({ kind: "turnstile", sitekey: sk, action: el.getAttribute("data-action") || null, element: el.tagName.toLowerCase(), provider: "cloudflare" });
        }
        for (const f of Array.from(document.querySelectorAll('iframe[src*="challenges.cloudflare.com"]'))) {
          const src = (f as any).src;
          const m = /\/turnstile\/[^/]+\/([a-zA-Z0-9]+)/.exec(src);
          if (m && !widgets.some((w) => w.sitekey === m[1])) widgets.push({ kind: "turnstile", sitekey: m[1], element: "iframe", provider: "cloudflare" });
        }
        // Arkose / FunCaptcha
        for (const f of Array.from(document.querySelectorAll('iframe[src*="arkoselabs.com"], iframe[src*="funcaptcha.com"]'))) {
          const src = (f as any).src;
          const m = /[?&]public_key=([^&]+)/.exec(src);
          widgets.push({ kind: "funcaptcha", sitekey: m?.[1] ?? null, element: "iframe", provider: "arkose" });
        }
        // GeeTest
        for (const el of Array.from(document.querySelectorAll(".geetest_holder, [data-gt]"))) {
          widgets.push({ kind: "geetest", sitekey: el.getAttribute("data-gt") || null, element: el.tagName.toLowerCase(), provider: "geetest" });
        }
        // Image captcha + text input (heuristic: img followed by input of certain names)
        for (const img of Array.from(document.querySelectorAll("img"))) {
          const s = (img as any).src || "";
          if (!/captcha/i.test(s) && !/captcha/i.test(img.id) && !/captcha/i.test((img as any).alt ?? "")) continue;
          widgets.push({ kind: "image-captcha", imageUrl: s, imgSelector: `img#${img.id}` || `img[src="${s}"]`, inputHint: "look for an adjacent <input> named captcha/code/verify" });
        }
        return { widgets, hiddenInputs: { recaptcha: !!document.querySelector("textarea#g-recaptcha-response"), hcaptcha: !!document.querySelector('textarea[name="h-captcha-response"]'), turnstile: !!document.querySelector('input[name="cf-turnstile-response"]') } };
      });
      return ok({ ...data, count: data.widgets.length });
    },
  },
  {
    name: "captcha_solve",
    description: "Solve a captcha using 2Captcha / Anti-Captcha / CapSolver (the same APIs Burp captcha extensions use). Pass service + API key + kind + sitekey. The returned token is NOT yet injected — call captcha_inject_token or pass autoInject:true to do both at once.",
    schema: z.object({
      service: z.enum(["2captcha", "anticaptcha", "capsolver"]),
      apiKey: z.string(),
      kind: z.enum(["recaptcha-v2", "recaptcha-v3", "hcaptcha", "turnstile"]),
      sitekey: z.string(),
      pageUrl: z.string().url().optional().describe("defaults to current page URL"),
      recaptchaAction: z.string().optional().describe("for v3"),
      recaptchaMinScore: z.number().optional().describe("for v3, e.g. 0.3"),
      timeoutMs: z.number().int().positive().optional().describe("default 180000 (3 min)"),
      autoInject: z.boolean().optional().describe("after solving, inject the token into the hidden form input and fire the callback"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const pageUrl = a.pageUrl ?? s.page.url();
      try {
        const t0 = Date.now();
        const { token } = await solveToken(s, a.service, a.apiKey, a.kind, a.sitekey, pageUrl, { action: a.recaptchaAction, minScore: a.recaptchaMinScore }, a.timeoutMs ?? 180000);
        const elapsed = Date.now() - t0;
        if (a.autoInject) {
          await s.page.evaluate(({ token, kind }: any) => {
            const inject = (sel: string, name: string) => { const el = document.querySelector(sel) as any; if (el) { el.value = token; el.style.display = ""; el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); } };
            if (kind === "recaptcha-v2" || kind === "recaptcha-v3") inject("textarea#g-recaptcha-response, textarea[name=g-recaptcha-response]", "g-recaptcha-response");
            else if (kind === "hcaptcha") inject('textarea[name="h-captcha-response"], textarea[name="g-recaptcha-response"]', "h-captcha-response");
            else if (kind === "turnstile") inject('input[name="cf-turnstile-response"]', "cf-turnstile-response");
            // Fire callbacks if present
            try { const g = (window as any).grecaptcha; if (kind.startsWith("recaptcha") && g?.getResponse) { /* usually auto-callback via DOM */ } } catch {}
            try { const el = document.querySelector(".g-recaptcha") as any; const cb = el?.getAttribute?.("data-callback"); if (cb && (window as any)[cb]) (window as any)[cb](token); } catch {}
          }, { token, kind: a.kind });
        }
        return ok({ solved: true, service: a.service, kind: a.kind, elapsedMs: elapsed, tokenLength: token.length, tokenPreview: token.slice(0, 40) + "...", injected: !!a.autoInject, token });
      } catch (e: any) { return err(e?.message ?? String(e)); }
    },
  },
  {
    name: "captcha_solve_image",
    description: "Solve a classic image/text captcha. Downloads the image, sends it to the chosen service (2captcha/anticaptcha/capsolver), returns the decoded text. If inputSelector is given, also types the answer in and clicks submitSelector if given.",
    schema: z.object({
      service: z.enum(["2captcha", "anticaptcha", "capsolver"]),
      apiKey: z.string(),
      imageUrl: z.string().url(),
      inputSelector: z.string().optional(),
      submitSelector: z.string().optional(),
      caseSensitive: z.boolean().optional(),
      numeric: z.boolean().optional(),
      minLength: z.number().int().positive().optional(),
      maxLength: z.number().int().positive().optional(),
      timeoutMs: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const imgR = await s.context.request.fetch(a.imageUrl, { ignoreHTTPSErrors: true });
        const body = await imgR.body();
        const b64 = body.toString("base64");
        const timeout = a.timeoutMs ?? 120000;
        let text: string;
        if (a.service === "2captcha") {
          const params: Record<string, string> = { method: "base64", body: b64 };
          if (a.caseSensitive) params.regsense = "1";
          if (a.numeric) params.numeric = "1";
          if (a.minLength) params.min_len = String(a.minLength);
          if (a.maxLength) params.max_len = String(a.maxLength);
          text = (await solve2captcha(s, a.apiKey, params, timeout)).token;
        } else if (a.service === "anticaptcha") {
          text = (await solveAntiCaptcha(s, a.apiKey, { type: "ImageToTextTask", body: b64, case: a.caseSensitive ?? false, numeric: a.numeric ? 1 : 0, minLength: a.minLength ?? 0, maxLength: a.maxLength ?? 0 }, timeout)).token;
        } else {
          text = (await solveCapSolver(s, a.apiKey, { type: "ImageToTextTask", body: b64, module: "common" }, timeout)).token;
        }
        if (a.inputSelector) await s.page.fill(a.inputSelector, text);
        if (a.submitSelector) await s.page.click(a.submitSelector);
        return ok({ solved: true, text, service: a.service });
      } catch (e: any) { return err(e?.message ?? String(e)); }
    },
  },
  {
    name: "captcha_inject_token",
    description: "Manually inject a captcha token into the page's hidden response field (for reCAPTCHA / hCaptcha / Turnstile) and fire the configured callback. Use when you solved the captcha some other way and just need to drop the token in.",
    schema: z.object({
      token: z.string(),
      kind: z.enum(["recaptcha-v2", "recaptcha-v3", "hcaptcha", "turnstile", "funcaptcha", "geetest"]),
      callbackName: z.string().optional().describe("optional JS function name to call with the token"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const result = await s.page.evaluate(({ token, kind, callbackName }: any) => {
        const fired: string[] = [];
        const inject = (sel: string) => { for (const el of Array.from(document.querySelectorAll(sel))) { (el as any).value = token; (el as any).style.display = ""; el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); fired.push(sel); } };
        if (kind === "recaptcha-v2" || kind === "recaptcha-v3") inject("textarea#g-recaptcha-response, textarea[name=g-recaptcha-response]");
        else if (kind === "hcaptcha") inject('textarea[name="h-captcha-response"], textarea[name="g-recaptcha-response"]');
        else if (kind === "turnstile") inject('input[name="cf-turnstile-response"]');
        else if (kind === "funcaptcha") inject('input[name="fc-token"], textarea[name="fc-token"]');
        if (callbackName && (window as any)[callbackName]) { try { (window as any)[callbackName](token); fired.push(`callback:${callbackName}`); } catch (e: any) { fired.push(`callback-error:${e.message}`); } }
        // Try to auto-fire data-callback on reCAPTCHA
        if (kind === "recaptcha-v2") { const el = document.querySelector(".g-recaptcha") as any; const cb = el?.getAttribute?.("data-callback"); if (cb && (window as any)[cb]) { try { (window as any)[cb](token); fired.push(`data-callback:${cb}`); } catch {} } }
        return fired;
      }, { token: a.token, kind: a.kind, callbackName: a.callbackName });
      return ok({ injected: result });
    },
  },
  {
    name: "captcha_wait_for_token",
    description: "Poll the hidden response field until a token appears (useful if a human is solving the captcha in the live-view, or if an in-page script will populate it).",
    schema: z.object({
      kind: z.enum(["recaptcha-v2", "recaptcha-v3", "hcaptcha", "turnstile"]),
      timeoutMs: z.number().int().positive().optional().describe("default 120000 (2 min)"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const sel = a.kind === "turnstile" ? 'input[name="cf-turnstile-response"]'
        : a.kind === "hcaptcha" ? 'textarea[name="h-captcha-response"]'
        : "textarea#g-recaptcha-response";
      try {
        const token = await s.page.waitForFunction((sel: string) => { const el = document.querySelector(sel) as any; return el && el.value ? el.value : null; }, sel, { timeout: a.timeoutMs ?? 120000, polling: 500 });
        return ok({ token: await token.jsonValue() });
      } catch (e: any) { return err(`no token after ${a.timeoutMs ?? 120000}ms`); }
    },
  },
  {
    name: "captcha_balance",
    description: "Check your remaining credit at a captcha service.",
    schema: z.object({ service: z.enum(["2captcha", "anticaptcha", "capsolver"]), apiKey: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        if (a.service === "2captcha") {
          const r = await s.context.request.fetch(`https://2captcha.com/res.php?key=${a.apiKey}&action=getbalance&json=1`, { ignoreHTTPSErrors: true });
          return ok(JSON.parse(await r.text()));
        } else if (a.service === "anticaptcha") {
          const r = await s.context.request.fetch("https://api.anti-captcha.com/getBalance", { method: "POST", data: JSON.stringify({ clientKey: a.apiKey }), headers: { "content-type": "application/json" }, ignoreHTTPSErrors: true } as any);
          return ok(JSON.parse(await r.text()));
        } else {
          const r = await s.context.request.fetch("https://api.capsolver.com/getBalance", { method: "POST", data: JSON.stringify({ clientKey: a.apiKey }), headers: { "content-type": "application/json" }, ignoreHTTPSErrors: true } as any);
          return ok(JSON.parse(await r.text()));
        }
      } catch (e: any) { return err(e?.message ?? String(e)); }
    },
  },
  {
    name: "captcha_report",
    description: "Report a captcha as good or bad to the service (helps your account's accuracy stats + sometimes gets a refund on bad solves).",
    schema: z.object({ service: z.enum(["2captcha", "anticaptcha", "capsolver"]), apiKey: z.string(), id: z.string(), good: z.boolean(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        if (a.service === "2captcha") {
          const action = a.good ? "reportgood" : "reportbad";
          const r = await s.context.request.fetch(`https://2captcha.com/res.php?key=${a.apiKey}&action=${action}&id=${a.id}&json=1`, { ignoreHTTPSErrors: true });
          return ok(JSON.parse(await r.text()));
        } else if (a.service === "anticaptcha") {
          const endpoint = a.good ? "reportCorrectRecaptcha" : "reportIncorrectRecaptcha";
          const r = await s.context.request.fetch(`https://api.anti-captcha.com/${endpoint}`, { method: "POST", data: JSON.stringify({ clientKey: a.apiKey, taskId: Number(a.id) }), headers: { "content-type": "application/json" }, ignoreHTTPSErrors: true } as any);
          return ok(JSON.parse(await r.text()));
        } else {
          const r = await s.context.request.fetch(a.good ? "https://api.capsolver.com/feedbackTask" : "https://api.capsolver.com/feedbackTask", { method: "POST", data: JSON.stringify({ clientKey: a.apiKey, taskId: a.id, result: { invalid: !a.good } }), headers: { "content-type": "application/json" }, ignoreHTTPSErrors: true } as any);
          return ok(JSON.parse(await r.text()));
        }
      } catch (e: any) { return err(e?.message ?? String(e)); }
    },
  },
];
