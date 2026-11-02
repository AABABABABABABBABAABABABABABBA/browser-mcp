import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional().describe("session id (uses default if omitted)") };

export const browserTools: ToolDef[] = [
  {
    name: "browser_open",
    description: "Open a new browser session. Returns a sessionId. Set headless:false to pop open a real visible Chromium window (works where you have a display). Set recordVideoDir to save a .webm of the session on close.",
    schema: z.object({
      userAgent: z.string().optional(),
      viewportWidth: z.number().int().positive().optional(),
      viewportHeight: z.number().int().positive().optional(),
      extraHeaders: z.record(z.string()).optional(),
      proxy: z.string().optional().describe("e.g. http://127.0.0.1:8080"),
      ignoreHttpsErrors: z.boolean().optional(),
      headless: z.boolean().optional().describe("default true. false opens a visible window on machines with a display"),
      recordVideoDir: z.string().optional().describe("directory to save a .webm video of the session (written on close)"),
    }),
    handler: async (a) => {
      const s = await hub.openSession({
        userAgent: a.userAgent,
        viewport: a.viewportWidth && a.viewportHeight ? { width: a.viewportWidth, height: a.viewportHeight } : undefined,
        extraHeaders: a.extraHeaders,
        proxy: a.proxy,
        ignoreHttpsErrors: a.ignoreHttpsErrors,
        headless: a.headless,
        recordVideoDir: a.recordVideoDir,
      });
      return ok({ sessionId: s.id, headless: a.headless ?? true, createdAt: s.createdAt });
    },
  },
  {
    name: "browser_list_sessions",
    description: "List all open browser sessions.",
    schema: z.object({}),
    handler: async () => ok(hub.listSessions()),
  },
  {
    name: "browser_close",
    description: "Close a browser session.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => { await hub.closeSession(a.sessionId); return ok("closed"); },
  },
  {
    name: "browser_navigate",
    description: "Navigate the session to a URL and wait for load.",
    schema: z.object({
      url: z.string().url(),
      waitUntil: z.enum(["load", "domcontentloaded", "networkidle", "commit"]).optional(),
      timeoutMs: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const resp = await s.page.goto(a.url, { waitUntil: a.waitUntil ?? "domcontentloaded", timeout: a.timeoutMs ?? 30000 });
      return ok({
        url: s.page.url(),
        status: resp?.status() ?? null,
        statusText: resp?.statusText() ?? null,
        headers: resp ? await resp.allHeaders() : null,
      });
    },
  },
  {
    name: "browser_back",
    description: "Browser go back.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => { const s = hub.getSession(a.sessionId); await s.page.goBack(); return ok(s.page.url()); },
  },
  {
    name: "browser_forward",
    description: "Browser go forward.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => { const s = hub.getSession(a.sessionId); await s.page.goForward(); return ok(s.page.url()); },
  },
  {
    name: "browser_reload",
    description: "Reload the current page.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => { const s = hub.getSession(a.sessionId); await s.page.reload(); return ok(s.page.url()); },
  },
  {
    name: "browser_screenshot",
    description: "Capture a PNG of the BROWSER PAGE ONLY — just what's rendered in the viewport, not the OS desktop. Default is viewport-sized (what a user sees). Options: fullPage to include everything that scrolls, selector to capture a single element, clip to crop a rect.",
    schema: z.object({
      fullPage: z.boolean().optional().describe("default false — capture only the viewport (what the browser shows). true includes offscreen scroll area."),
      selector: z.string().optional().describe("CSS selector to capture a specific element only"),
      clip: z.object({ x: z.number(), y: z.number(), width: z.number(), height: z.number() }).optional(),
      omitBackground: z.boolean().optional().describe("transparent background instead of white"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      let buf: Buffer;
      if (a.selector) {
        const el = await s.page.$(a.selector);
        if (!el) return { content: [{ type: "text", text: `error: element not found: ${a.selector}` }], isError: true };
        buf = await el.screenshot({ type: "png", omitBackground: a.omitBackground });
      } else {
        buf = await s.page.screenshot({
          fullPage: a.fullPage ?? false,
          clip: a.clip,
          omitBackground: a.omitBackground,
          type: "png",
        });
      }
      return { content: [{ type: "image", data: buf.toString("base64"), mimeType: "image/png" }] };
    },
  },
  {
    name: "browser_get_html",
    description: "Return the current page's HTML.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => ok(await hub.getSession(a.sessionId).page.content()),
  },
  {
    name: "browser_get_text",
    description: "Return the visible text of the current page.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => ok(await hub.getSession(a.sessionId).page.innerText("body")),
  },
  {
    name: "browser_get_url",
    description: "Return the current URL.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => ok(hub.getSession(a.sessionId).page.url()),
  },
  {
    name: "browser_click",
    description: "Click an element by CSS selector.",
    schema: z.object({ selector: z.string(), timeoutMs: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.click(a.selector, { timeout: a.timeoutMs ?? 10000 }); return ok("clicked"); },
  },
  {
    name: "browser_type",
    description: "Type text into an element.",
    schema: z.object({ selector: z.string(), text: z.string(), delay: z.number().optional(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.fill(a.selector, a.text); return ok("typed"); },
  },
  {
    name: "browser_press",
    description: "Press a keyboard key, e.g. Enter, Tab, Escape, ArrowDown.",
    schema: z.object({ key: z.string(), selector: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      if (a.selector) await s.page.press(a.selector, a.key);
      else await s.page.keyboard.press(a.key);
      return ok("pressed");
    },
  },
  {
    name: "browser_select",
    description: "Pick an option from a <select>.",
    schema: z.object({ selector: z.string(), value: z.string(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.selectOption(a.selector, a.value); return ok("selected"); },
  },
  {
    name: "browser_wait_for",
    description: "Wait for a selector, URL, or page load state.",
    schema: z.object({
      selector: z.string().optional(),
      url: z.string().optional(),
      state: z.enum(["load", "domcontentloaded", "networkidle"]).optional(),
      timeoutMs: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const t = a.timeoutMs ?? 15000;
      if (a.selector) await s.page.waitForSelector(a.selector, { timeout: t });
      else if (a.url) await s.page.waitForURL(a.url, { timeout: t });
      else if (a.state) await s.page.waitForLoadState(a.state, { timeout: t });
      else return err("one of selector/url/state is required");
      return ok("waited");
    },
  },
  {
    name: "browser_evaluate",
    description: "Run arbitrary JavaScript inside the page. The expression's return value is JSON-serialized.",
    schema: z.object({ expression: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const result = await s.page.evaluate((code) => {
        // pumppet
        const fn = new Function(`return (async () => { return (${code}); })();`);
        return fn();
      }, a.expression);
      return ok({ result });
    },
  },
  {
    name: "browser_cookies_get",
    description: "Get the session cookies.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => ok(await hub.getSession(a.sessionId).context.cookies()),
  },
  {
    name: "browser_cookies_set",
    description: "Set one or more cookies.",
    schema: z.object({
      cookies: z.array(z.object({
        name: z.string(),
        value: z.string(),
        domain: z.string().optional(),
        path: z.string().optional(),
        url: z.string().optional(),
        httpOnly: z.boolean().optional(),
        secure: z.boolean().optional(),
        sameSite: z.enum(["Strict", "Lax", "None"]).optional(),
      })),
      ...sessionArg,
    }),
    handler: async (a) => {
      await hub.getSession(a.sessionId).context.addCookies(a.cookies as any);
      return ok("set");
    },
  },
  {
    name: "browser_cookies_clear",
    description: "Clear all cookies in the session.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).context.clearCookies(); return ok("cleared"); },
  },
  {
    name: "browser_set_headers",
    description: "Set extra HTTP headers for all future requests in the session.",
    schema: z.object({ headers: z.record(z.string()), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).context.setExtraHTTPHeaders(a.headers); return ok("set"); },
  },
  {
    name: "browser_set_user_agent",
    description: "Set the user-agent string for subsequent requests.",
    schema: z.object({ userAgent: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.context.setExtraHTTPHeaders({ "User-Agent": a.userAgent });
      return ok("set");
    },
  },
  {
    name: "browser_dom_query",
    description: "Query one or more elements, returning attributes, text, and bounding box.",
    schema: z.object({ selector: z.string(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const data = await s.page.$$eval(
        a.selector,
        (nodes, limit) => nodes.slice(0, limit as number).map((n: any) => ({
          tag: n.tagName.toLowerCase(),
          text: (n.innerText || "").slice(0, 400),
          attrs: Object.fromEntries(Array.from(n.attributes).map((at: any) => [at.name, at.value])),
          outerHtml: n.outerHTML.slice(0, 2000),
        })),
        a.limit ?? 20,
      );
      return ok(data);
    },
  },
];
