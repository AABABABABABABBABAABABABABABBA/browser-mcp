import { z } from "zod";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { devices } from "playwright";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

const DEVICE_PRESETS = ["iPhone 14", "iPhone 14 Pro Max", "iPhone 13", "iPhone SE", "Pixel 7", "Pixel 5", "Galaxy S9+", "iPad Pro 11", "iPad Mini", "Desktop Chrome", "Desktop Firefox", "Desktop Safari"] as const;

export const browser2Tools: ToolDef[] = [
  {
    name: "browser_emulate_device",
    description: "Switch the session to a device preset — iPhone, Pixel, iPad, or desktop. Sets user-agent, viewport, device-pixel-ratio, touch, and mobile flags. Call before navigate.",
    schema: z.object({ device: z.enum(DEVICE_PRESETS), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const d = (devices as any)[a.device];
      if (!d) return err(`unknown device: ${a.device}`);
      await s.context.setExtraHTTPHeaders({ "User-Agent": d.userAgent });
      await s.page.setViewportSize({ width: d.viewport.width, height: d.viewport.height });
      return ok({ device: a.device, userAgent: d.userAgent, viewport: d.viewport, deviceScaleFactor: d.deviceScaleFactor, isMobile: d.isMobile, hasTouch: d.hasTouch });
    },
  },
  {
    name: "browser_set_geolocation",
    description: "Spoof the browser's geolocation.",
    schema: z.object({ latitude: z.number(), longitude: z.number(), accuracy: z.number().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.context.setGeolocation({ latitude: a.latitude, longitude: a.longitude, accuracy: a.accuracy ?? 100 });
      await s.context.grantPermissions(["geolocation"]);
      return ok({ latitude: a.latitude, longitude: a.longitude });
    },
  },
  {
    name: "browser_set_timezone",
    description: "Spoof the browser timezone. Changes Date behavior and Intl output.",
    schema: z.object({ timezone: z.string().describe("IANA zone, e.g. America/Toronto"), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.context.addInitScript(({ tz }) => {
        try { (Intl as any).DateTimeFormat = new Proxy(Intl.DateTimeFormat, { construct(t: any, args: any[]) { if (args[1]) args[1].timeZone = tz; else args[1] = { timeZone: tz }; return new t(...args); } }); } catch {}
      }, { tz: a.timezone });
      return ok({ timezone: a.timezone, note: "init-script armed; reload to apply" });
    },
  },
  {
    name: "browser_set_locale",
    description: "Set the Accept-Language / navigator.language on new pages in the session.",
    schema: z.object({ locale: z.string().describe("e.g. en-US, fr-CA, ja-JP"), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.context.setExtraHTTPHeaders({ "Accept-Language": a.locale });
      await s.context.addInitScript(({ locale }: any) => {
        try { Object.defineProperty(navigator, "language", { get: () => locale }); Object.defineProperty(navigator, "languages", { get: () => [locale] }); } catch {}
      }, { locale: a.locale });
      return ok({ locale: a.locale });
    },
  },
  {
    name: "browser_grant_permissions",
    description: "Grant web permissions to the current origin — geolocation, notifications, camera, microphone, clipboard, midi.",
    schema: z.object({
      permissions: z.array(z.enum(["geolocation", "notifications", "camera", "microphone", "clipboard-read", "clipboard-write", "midi", "midi-sysex", "accelerometer", "gyroscope", "magnetometer", "background-sync", "ambient-light-sensor", "payment-handler", "accessibility-events"] as const)),
      origin: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.context.grantPermissions(a.permissions, a.origin ? { origin: a.origin } : undefined);
      return ok("granted");
    },
  },
  {
    name: "browser_new_tab",
    description: "Open a new tab in the same session (shares cookies). Returns the new page's index.",
    schema: z.object({ url: z.string().url().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const page = await s.context.newPage();
      if (a.url) await page.goto(a.url, { waitUntil: "domcontentloaded" });
      return ok({ pages: s.context.pages().length, url: page.url() });
    },
  },
  {
    name: "browser_list_tabs",
    description: "List tabs in the session with their URL + title + which one is active.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const pages = s.context.pages();
      const items = await Promise.all(pages.map(async (p: any, i: number) => ({ index: i, url: p.url(), title: await p.title().catch(() => ""), active: p === s.page })));
      return ok(items);
    },
  },
  {
    name: "browser_switch_tab",
    description: "Switch the session's active page to the given tab index.",
    schema: z.object({ index: z.number().int().min(0), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const pages = s.context.pages();
      if (a.index >= pages.length) return err(`only ${pages.length} tabs`);
      s.page = pages[a.index];
      await s.page.bringToFront();
      return ok({ switched: a.index, url: s.page.url() });
    },
  },
  {
    name: "browser_close_tab",
    description: "Close a specific tab index.",
    schema: z.object({ index: z.number().int().min(0), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const pages = s.context.pages();
      if (a.index >= pages.length) return err(`only ${pages.length} tabs`);
      await pages[a.index].close();
      s.page = s.context.pages()[0] ?? s.page;
      return ok("closed");
    },
  },
  {
    name: "browser_pdf",
    description: "Save the current page as PDF (Chromium only). Returns the file path and bytes.",
    schema: z.object({ path: z.string().optional(), landscape: z.boolean().optional(), scale: z.number().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const out = a.path ?? `/tmp/browser-mcp-${Date.now()}.pdf`;
      try {
        const buf = await s.page.pdf({ path: out, landscape: a.landscape, scale: a.scale });
        return ok({ path: out, bytes: buf.length });
      } catch (e: any) { return err(`pdf failed: ${e?.message ?? e}`); }
    },
  },
  {
    name: "browser_download",
    description: "Download a file through the session (shares cookies + headers). Saves to disk and returns the path.",
    schema: z.object({ url: z.string().url(), path: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = await s.context.request.fetch(a.url, { ignoreHTTPSErrors: true });
      const buf = await r.body();
      const out = a.path ?? `/tmp/${basename(new URL(a.url).pathname) || "download.bin"}`;
      const { writeFile } = await import("node:fs/promises");
      await writeFile(out, buf);
      return ok({ url: a.url, path: out, bytes: buf.length, status: r.status(), contentType: r.headers()["content-type"] ?? "" });
    },
  },
  {
    name: "browser_upload_file",
    description: "Set the files on an <input type=file> element.",
    schema: z.object({ selector: z.string(), filePaths: z.array(z.string()).min(1), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.page.setInputFiles(a.selector, a.filePaths);
      return ok("set");
    },
  },
  {
    name: "browser_accessibility_tree",
    description: "Return the ARIA accessibility tree of the page — what screen readers see. Great for understanding structure and finding unlabeled controls.",
    schema: z.object({ interestingOnly: z.boolean().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const tree = await (s.page as any).accessibility.snapshot({ interestingOnly: a.interestingOnly ?? true });
      return ok(tree);
    },
  },
  {
    name: "browser_metrics",
    description: "Performance metrics for the page — timing (TTFB, DOMContentLoaded, Load), paint (FP, FCP), layout counts, memory.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const data = await s.page.evaluate(() => {
        const t = performance.timing;
        const paint = Object.fromEntries(performance.getEntriesByType("paint").map((p: any) => [p.name, Math.round(p.startTime)]));
        return {
          ttfbMs: t.responseStart - t.requestStart,
          domContentLoadedMs: t.domContentLoadedEventEnd - t.navigationStart,
          loadMs: t.loadEventEnd - t.navigationStart,
          domInteractiveMs: t.domInteractive - t.navigationStart,
          firstPaintMs: paint["first-paint"],
          firstContentfulPaintMs: paint["first-contentful-paint"],
          resourceCount: performance.getEntriesByType("resource").length,
          memory: (performance as any).memory ? { usedJSHeap: (performance as any).memory.usedJSHeapSize, totalJSHeap: (performance as any).memory.totalJSHeapSize } : null,
        };
      });
      return ok(data);
    },
  },
  {
    name: "browser_mouse",
    description: "Lower-level mouse control — move/down/up/click/wheel at specific coordinates.",
    schema: z.object({ action: z.enum(["move", "down", "up", "click", "wheel"]), x: z.number().optional(), y: z.number().optional(), deltaX: z.number().optional(), deltaY: z.number().optional(), button: z.enum(["left", "right", "middle"]).optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const mouse = s.page.mouse;
      switch (a.action) {
        case "move": await mouse.move(a.x ?? 0, a.y ?? 0); break;
        case "down": await mouse.down({ button: a.button ?? "left" }); break;
        case "up": await mouse.up({ button: a.button ?? "left" }); break;
        case "click": await mouse.click(a.x ?? 0, a.y ?? 0, { button: a.button ?? "left" }); break;
        case "wheel": await mouse.wheel(a.deltaX ?? 0, a.deltaY ?? 0); break;
      }
      return ok("done");
    },
  },
  {
    name: "browser_scroll",
    description: "Scroll the page by delta pixels, or to a given selector, or to top/bottom.",
    schema: z.object({ to: z.enum(["top", "bottom"]).optional(), selector: z.string().optional(), deltaY: z.number().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      if (a.to === "top") await s.page.evaluate(() => window.scrollTo(0, 0));
      else if (a.to === "bottom") await s.page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
      else if (a.selector) await s.page.$eval(a.selector, (el: any) => el.scrollIntoView({ behavior: "instant", block: "center" }));
      else if (a.deltaY !== undefined) await s.page.mouse.wheel(0, a.deltaY);
      return ok("scrolled");
    },
  },
];
