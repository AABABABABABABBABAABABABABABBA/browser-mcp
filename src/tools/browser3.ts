import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

export const browser3Tools: ToolDef[] = [
  {
    name: "browser_hover",
    description: "Hover the cursor over an element — triggers CSS :hover state and JS hover handlers (menus, tooltips).",
    schema: z.object({ selector: z.string(), timeoutMs: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.hover(a.selector, { timeout: a.timeoutMs ?? 10000 }); return ok("hovered"); },
  },
  {
    name: "browser_double_click",
    description: "Double-click an element.",
    schema: z.object({ selector: z.string(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.dblclick(a.selector); return ok("double-clicked"); },
  },
  {
    name: "browser_right_click",
    description: "Right-click (context menu) an element.",
    schema: z.object({ selector: z.string(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.click(a.selector, { button: "right" }); return ok("right-clicked"); },
  },
  {
    name: "browser_focus",
    description: "Focus an element without clicking.",
    schema: z.object({ selector: z.string(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.focus(a.selector); return ok("focused"); },
  },
  {
    name: "browser_drag",
    description: "Drag one element onto another.",
    schema: z.object({ from: z.string(), to: z.string(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.dragAndDrop(a.from, a.to); return ok("dragged"); },
  },
  {
    name: "browser_type_slow",
    description: "Type text character-by-character with a delay to look human. Good for sites that bot-detect fast typing.",
    schema: z.object({ selector: z.string(), text: z.string(), delayMs: z.number().int().min(0).max(500).optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.page.focus(a.selector);
      await s.page.keyboard.type(a.text, { delay: a.delayMs ?? 50 });
      return ok("typed");
    },
  },
  {
    name: "browser_fill_form",
    description: "Fill a form by passing a map of CSS selectors → values. Handles text inputs, textareas, selects, radios, checkboxes.",
    schema: z.object({
      fields: z.record(z.union([z.string(), z.boolean(), z.array(z.string())])),
      submitSelector: z.string().optional().describe("if given, click it after filling"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const results: Array<{ selector: string; ok: boolean; error?: string }> = [];
      for (const [sel, val] of Object.entries(a.fields)) {
        try {
          const el = s.page.locator(sel).first();
          const tag = await el.evaluate((e: any) => e.tagName.toLowerCase()).catch(() => "");
          const type = await el.evaluate((e: any) => e.type ?? "").catch(() => "");
          if (type === "checkbox" || type === "radio") {
            if (val === true) await el.check(); else if (val === false) await el.uncheck();
          } else if (tag === "select") {
            await el.selectOption(val as any);
          } else {
            await el.fill(String(val));
          }
          results.push({ selector: sel, ok: true });
        } catch (e: any) { results.push({ selector: sel, ok: false, error: e?.message ?? String(e) }); }
      }
      if (a.submitSelector) await s.page.click(a.submitSelector);
      return ok({ filled: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length, results });
    },
  },
  {
    name: "browser_submit_form",
    description: "Submit a form by selector (or the first form on the page). Waits for navigation if that's the result.",
    schema: z.object({ selector: z.string().optional(), waitForNavigation: z.boolean().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const sel = a.selector ?? "form";
      if (a.waitForNavigation !== false) {
        await Promise.all([
          s.page.waitForLoadState("domcontentloaded").catch(() => null),
          s.page.evaluate((sel: any) => { const f = document.querySelector(sel) as any; if (f) f.submit(); }, sel),
        ]);
      } else {
        await s.page.evaluate((sel: any) => { const f = document.querySelector(sel) as any; if (f) f.submit(); }, sel);
      }
      return ok({ url: s.page.url() });
    },
  },
  {
    name: "browser_check",
    description: "Check a checkbox or radio button.",
    schema: z.object({ selector: z.string(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.check(a.selector); return ok("checked"); },
  },
  {
    name: "browser_uncheck",
    description: "Uncheck a checkbox.",
    schema: z.object({ selector: z.string(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.uncheck(a.selector); return ok("unchecked"); },
  },
  {
    name: "browser_click_by_text",
    description: "Click the first element whose visible text matches (or contains) the given string. No need to know the selector.",
    schema: z.object({ text: z.string(), exact: z.boolean().optional(), tag: z.string().optional().describe("restrict to a tag, e.g. 'a', 'button'"), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const loc = a.tag ? s.page.locator(a.tag).filter({ hasText: a.exact ? new RegExp(`^${a.text}$`) : a.text }) : s.page.getByText(a.text, { exact: a.exact ?? false });
      await loc.first().click();
      return ok("clicked");
    },
  },
  {
    name: "browser_find_by_text",
    description: "Find elements by visible text; returns their tag, href (if link), aria label, and bounding box.",
    schema: z.object({ text: z.string(), exact: z.boolean().optional(), limit: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const list = s.page.getByText(a.text, { exact: a.exact ?? false });
      const count = Math.min(await list.count(), a.limit ?? 10);
      const results: any[] = [];
      for (let i = 0; i < count; i++) {
        const el = list.nth(i);
        const info = await el.evaluate((e: any) => ({ tag: e.tagName.toLowerCase(), href: e.href ?? null, text: (e.innerText ?? "").slice(0, 200), id: e.id || null, class: e.className?.toString?.() || null, ariaLabel: e.getAttribute("aria-label"), bbox: (() => { const b = e.getBoundingClientRect(); return { x: b.x, y: b.y, w: b.width, h: b.height }; })() })).catch(() => null);
        if (info) results.push(info);
      }
      return ok(results);
    },
  },
  {
    name: "browser_links",
    description: "List all <a href> on the page: text, href (resolved absolute), and whether same-origin.",
    schema: z.object({ sameOriginOnly: z.boolean().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const data = await s.page.$$eval("a[href]", (as: any[]) => as.map((a: any) => ({ text: (a.innerText ?? "").trim().slice(0, 200), href: a.href, target: a.target || null })));
      let out = data;
      if (a.sameOriginOnly) {
        try { const origin = new URL(s.page.url()).origin; out = data.filter((l: any) => { try { return new URL(l.href).origin === origin; } catch { return false; } }); } catch {}
      }
      return ok({ count: out.length, links: out });
    },
  },
  {
    name: "browser_follow_link",
    description: "Click a link by matching its visible text (shortcut for 'click an <a> whose text contains X').",
    schema: z.object({ text: z.string(), exact: z.boolean().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.page.locator("a").filter({ hasText: a.exact ? new RegExp(`^${a.text}$`) : a.text }).first().click();
      return ok({ url: s.page.url() });
    },
  },
  {
    name: "browser_zoom",
    description: "Set the page zoom factor (CSS-level, via document.body.style.zoom).",
    schema: z.object({ factor: z.number().min(0.25).max(4).describe("1.0 = 100%"), ...sessionArg }),
    handler: async (a) => {
      await hub.getSession(a.sessionId).page.evaluate((f: any) => { (document.body as any).style.zoom = String(f); }, a.factor);
      return ok({ zoom: a.factor });
    },
  },
  {
    name: "browser_viewport_set",
    description: "Change the viewport size on the fly.",
    schema: z.object({ width: z.number().int().positive(), height: z.number().int().positive(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.setViewportSize({ width: a.width, height: a.height }); return ok({ width: a.width, height: a.height }); },
  },
  {
    name: "browser_set_offline",
    description: "Toggle network offline mode on the session.",
    schema: z.object({ offline: z.boolean(), ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).context.setOffline(a.offline); return ok({ offline: a.offline }); },
  },
  {
    name: "browser_dialog_handler",
    description: "Pre-set how dialogs (alert/confirm/prompt) are answered. Default is to dismiss. Can accept, dismiss, or send a specific prompt answer.",
    schema: z.object({
      action: z.enum(["accept", "dismiss", "accept_with"]),
      promptText: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      s.page.removeAllListeners("dialog");
      s.page.on("dialog", async (d: any) => {
        try {
          if (a.action === "accept") await d.accept();
          else if (a.action === "accept_with") await d.accept(a.promptText ?? "");
          else await d.dismiss();
        } catch { /* pumppet */ }
      });
      return ok({ action: a.action });
    },
  },
  {
    name: "browser_history_go",
    description: "Jump N entries in the session's history. Positive = forward, negative = back.",
    schema: z.object({ delta: z.number().int(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      let steps = Math.abs(a.delta);
      while (steps-- > 0) { if (a.delta > 0) await s.page.goForward(); else await s.page.goBack(); }
      return ok({ url: s.page.url() });
    },
  },
  {
    name: "browser_wait_for_response",
    description: "Wait until a response matching a URL regex comes back; return its status + body snippet. Useful for XHR-driven apps.",
    schema: z.object({ urlPattern: z.string(), timeoutMs: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const resp = await s.page.waitForResponse(new RegExp(a.urlPattern), { timeout: a.timeoutMs ?? 15000 });
      const body = await resp.text().catch(() => "");
      return ok({ status: resp.status(), url: resp.url(), bodySnippet: body.slice(0, 2000) });
    },
  },
  {
    name: "browser_record_start",
    description: "Open a NEW session with video recording enabled; returns the sessionId. Video is written as .webm when the session closes.",
    schema: z.object({
      dir: z.string().describe("output directory"),
      viewportWidth: z.number().int().positive().optional(),
      viewportHeight: z.number().int().positive().optional(),
      headless: z.boolean().optional(),
    }),
    handler: async (a) => {
      const s = await hub.openSession({
        viewport: a.viewportWidth && a.viewportHeight ? { width: a.viewportWidth, height: a.viewportHeight } : undefined,
        recordVideoDir: a.dir,
        headless: a.headless,
      });
      return ok({ sessionId: s.id, note: "video will be saved when the session is closed" });
    },
  },
  {
    name: "browser_cdp_endpoint",
    description: "Return the browser's Chrome DevTools Protocol WebSocket endpoint. Lets you point devtools (chrome://inspect) or any CDP client at the running Chromium.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const b: any = s.context.browser();
      if (!b) return err("no browser");
      const ws = typeof b.wsEndpoint === "function" ? b.wsEndpoint() : null;
      return ok({ wsEndpoint: ws, version: b.version?.() ?? null, note: ws ? "point chrome://inspect or any CDP client here" : "this browser build does not expose a ws endpoint" });
    },
  },
  {
    name: "browser_wait_for_url",
    description: "Wait until the current page URL matches a pattern.",
    schema: z.object({ pattern: z.string().describe("regex OR plain substring"), timeoutMs: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      await s.page.waitForURL((url) => new RegExp(a.pattern).test(url.toString()) || url.toString().includes(a.pattern), { timeout: a.timeoutMs ?? 15000 });
      return ok({ url: s.page.url() });
    },
  },
  {
    name: "browser_wait_idle",
    description: "Wait for network idle (no in-flight requests for 500ms).",
    schema: z.object({ timeoutMs: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      await hub.getSession(a.sessionId).page.waitForLoadState("networkidle", { timeout: a.timeoutMs ?? 15000 });
      return ok("idle");
    },
  },
  {
    name: "browser_bring_to_front",
    description: "If headful, bring the browser window to front.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => { await hub.getSession(a.sessionId).page.bringToFront(); return ok("fronted"); },
  },
];
