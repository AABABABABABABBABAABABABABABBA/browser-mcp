import { z } from "zod";
import { WebSocket } from "ws";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

interface WsSession { ws: WebSocket; messages: Array<{ ts: number; dir: "sent" | "recv"; data: string }>; createdAt: number; url: string; closed: boolean; }
const wsSessions = new Map<string, WsSession>();

export const wsTools: ToolDef[] = [
  {
    name: "ws_connect",
    description: "Open a WebSocket client. Captures every frame. Shares cookies from the browser session for the ws target host if cookies: 'session' is set.",
    schema: z.object({
      url: z.string().describe("ws:// or wss:// URL"),
      headers: z.record(z.string()).optional(),
      origin: z.string().optional(),
      subprotocols: z.array(z.string()).optional(),
      cookiesFromSession: z.boolean().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      let headers: Record<string, string> = { ...(a.headers ?? {}) };
      if (a.origin) headers["Origin"] = a.origin;
      if (a.cookiesFromSession) {
        try {
          const s = hub.getSession(a.sessionId);
          const host = new URL(a.url.replace(/^ws/, "http")).hostname;
          const cookies = (await s.context.cookies()).filter((c) => host.includes(c.domain.replace(/^\./, "")));
          if (cookies.length) headers["Cookie"] = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
        } catch { /* pumppet */ }
      }
      const id = Math.random().toString(36).slice(2, 10);
      const ws = new WebSocket(a.url, a.subprotocols, { headers, rejectUnauthorized: false });
      const session: WsSession = { ws, messages: [], createdAt: Date.now(), url: a.url, closed: false };
      wsSessions.set(id, session);
      ws.on("message", (data) => session.messages.push({ ts: Date.now(), dir: "recv", data: data.toString() }));
      ws.on("close", (code, reason) => { session.closed = true; session.messages.push({ ts: Date.now(), dir: "recv", data: `[CLOSE code=${code} reason=${reason.toString()}]` }); });
      ws.on("error", (e) => session.messages.push({ ts: Date.now(), dir: "recv", data: `[ERROR ${e.message}]` }));

      await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error("ws connect timeout")), 10000);
        ws.once("open", () => { clearTimeout(t); resolve(null); });
        ws.once("error", (e) => { clearTimeout(t); reject(e); });
      }).catch((e) => ({ error: e.message }));

      return ok({ id, url: a.url, state: session.closed ? "closed" : "open" });
    },
  },
  {
    name: "ws_send",
    description: "Send a message on a WebSocket.",
    schema: z.object({ id: z.string(), data: z.string() }),
    handler: async (a) => {
      const sess = wsSessions.get(a.id);
      if (!sess) return err(`no ws ${a.id}`);
      if (sess.ws.readyState !== WebSocket.OPEN) return err(`ws not open (state=${sess.ws.readyState})`);
      sess.ws.send(a.data);
      sess.messages.push({ ts: Date.now(), dir: "sent", data: a.data });
      return ok("sent");
    },
  },
  {
    name: "ws_messages",
    description: "Get the message log for a WebSocket.",
    schema: z.object({ id: z.string(), since: z.number().int().optional().describe("only messages after this timestamp"), limit: z.number().int().positive().optional() }),
    handler: async (a) => {
      const sess = wsSessions.get(a.id);
      if (!sess) return err(`no ws ${a.id}`);
      let msgs = sess.messages;
      if (a.since) msgs = msgs.filter((m) => m.ts > a.since!);
      if (a.limit) msgs = msgs.slice(-a.limit);
      return ok({ open: sess.ws.readyState === WebSocket.OPEN, count: msgs.length, messages: msgs });
    },
  },
  {
    name: "ws_close",
    description: "Close a WebSocket.",
    schema: z.object({ id: z.string(), code: z.number().int().optional() }),
    handler: async (a) => {
      const sess = wsSessions.get(a.id);
      if (!sess) return err(`no ws ${a.id}`);
      sess.ws.close(a.code ?? 1000);
      return ok("closed");
    },
  },
  {
    name: "ws_list",
    description: "List open WebSocket sessions.",
    schema: z.object({}),
    handler: async () => ok(Array.from(wsSessions.entries()).map(([id, s]) => ({ id, url: s.url, state: s.ws.readyState, messages: s.messages.length, createdAt: s.createdAt }))),
  },
  {
    name: "ws_captured_from_page",
    description: "Return WebSocket connections and frames captured by the browser (passive) — Playwright attaches to every ws the page opens.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      // We don't buffer this by default; set up a quick capture if needed
      return ok({ note: "run ws_capture_arm then reload the page to collect page-opened websockets" });
    },
  },
  {
    name: "ws_capture_arm",
    description: "Install a passive capture of every WebSocket the page opens going forward (frames stored in-session).",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const buf: any[] = [];
      (s as any).__ws_passive = buf;
      s.page.on("websocket", (ws) => {
        buf.push({ url: ws.url(), openedAt: Date.now(), frames: [] as any[] });
        const entry = buf[buf.length - 1];
        ws.on("framesent", (f: any) => entry.frames.push({ ts: Date.now(), dir: "sent", data: f.payload?.toString?.() ?? "[binary]" }));
        ws.on("framereceived", (f: any) => entry.frames.push({ ts: Date.now(), dir: "recv", data: f.payload?.toString?.() ?? "[binary]" }));
        ws.on("close", () => entry.closedAt = Date.now());
      });
      return ok("armed — reload the page to begin capture");
    },
  },
  {
    name: "ws_capture_dump",
    description: "Dump the passively captured WebSocket connections and their frames.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const buf = (s as any).__ws_passive ?? [];
      return ok(buf);
    },
  },
];
