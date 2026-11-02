import { z } from "zod";
import { createServer, Server, ServerResponse } from "node:http";
import type { CDPSession } from "playwright";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

interface LiveView {
  server: Server;
  port: number;
  cdp: CDPSession;
  subscribers: Set<ServerResponse>;
  latest: Buffer | null;
  wsSubscribers: Set<any>;
}

const views = new Map<string, LiveView>();

const PAGE_HTML = (title: string, startUrl: string) => `<!doctype html>
<html><head>
<meta charset="utf-8">
<title>browser-mcp live view — ${title}</title>
<style>
  html,body{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif;overflow:hidden;height:100%}
  .bar{position:fixed;top:0;left:0;right:0;height:34px;background:#222;display:flex;align-items:center;padding:0 10px;gap:8px;border-bottom:1px solid #333;z-index:10}
  .url{flex:1;background:#111;color:#bbb;padding:4px 8px;border-radius:4px;font-size:12px;font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .dot{width:10px;height:10px;background:#4c4;border-radius:50%}
  .dot.off{background:#c44}
  main{position:absolute;top:34px;left:0;right:0;bottom:0;display:flex;align-items:flex-start;justify-content:center;overflow:auto;background:#000}
  img{display:block;max-width:100%}
  .fps{font-size:11px;color:#888}
</style></head>
<body>
<div class="bar"><span class="dot" id="dot"></span><span class="url" id="url">${startUrl}</span><span class="fps" id="fps"></span></div>
<main><img id="view" src="/stream"></main>
<script>
let last=Date.now(), frames=0;
setInterval(async()=>{try{const r=await fetch('/status');const j=await r.json();document.getElementById('url').textContent=j.url;document.getElementById('dot').classList.toggle('off',!j.alive);document.getElementById('fps').textContent=j.fps.toFixed(1)+' fps';}catch(e){}},750);
const img=document.getElementById('view');
img.addEventListener('load',()=>{frames++;const now=Date.now();if(now-last>=1000){document.getElementById('fps').textContent=(frames*1000/(now-last)).toFixed(1)+' fps';frames=0;last=now;}});
// click forwarding to the backend
img.addEventListener('click',async e=>{const r=img.getBoundingClientRect();const sx=img.naturalWidth/r.width,sy=img.naturalHeight/r.height;await fetch('/click',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({x:(e.clientX-r.left)*sx,y:(e.clientY-r.top)*sy})});});
// keyboard forwarding
document.addEventListener('keydown',async e=>{if(e.target!==document.body&&e.target.tagName!=='BODY')return;await fetch('/key',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key:e.key})});});
</script>
</body></html>`;

export const liveViewTools: ToolDef[] = [
  {
    name: "liveview_start",
    description: "Start a local HTTP server that streams the browser session as a live MJPEG you can watch in any browser (open the returned URL). You see the page in near-real-time (~10 fps), navigations and interactions included. Clicking on the stream forwards clicks to the headless browser. Keys typed with no focus also forward.",
    schema: z.object({
      port: z.number().int().optional().describe("default: random free port"),
      quality: z.number().int().min(10).max(100).optional().describe("JPEG quality 10-100, default 60"),
      everyNthFrame: z.number().int().min(1).optional().describe("1=every frame, 2=every 2nd, etc. default 1"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      if (views.has(s.id)) return ok({ url: `http://127.0.0.1:${views.get(s.id)!.port}/`, note: "already running" });

      const cdp = await s.context.newCDPSession(s.page);
      await cdp.send("Page.enable");
      const subscribers = new Set<ServerResponse>();
      let latest: Buffer | null = null;

      cdp.on("Page.screencastFrame", async (params: any) => {
        const buf = Buffer.from(params.data, "base64");
        latest = buf;
        for (const res of subscribers) {
          try {
            res.write(`--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${buf.length}\r\n\r\n`);
            res.write(buf);
            res.write("\r\n");
          } catch { subscribers.delete(res); }
        }
        try { await cdp.send("Page.screencastFrameAck", { sessionId: params.sessionId }); } catch { /* pumppet */ }
      });

      await cdp.send("Page.startScreencast", {
        format: "jpeg",
        quality: a.quality ?? 60,
        everyNthFrame: a.everyNthFrame ?? 1,
      });

      const server = createServer(async (req, res) => {
        try {
          const url = req.url ?? "/";
          if (url === "/" || url === "/index.html") {
            const curSession = hub.getSession(a.sessionId);
            res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
            res.end(PAGE_HTML(curSession.page.url(), curSession.page.url()));
            return;
          }
          if (url === "/stream") {
            res.writeHead(200, {
              "content-type": "multipart/x-mixed-replace; boundary=frame",
              "cache-control": "no-cache", "connection": "close", "pragma": "no-cache",
            });
            subscribers.add(res);
            req.on("close", () => subscribers.delete(res));
            if (latest) {
              res.write(`--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${latest.length}\r\n\r\n`);
              res.write(latest); res.write("\r\n");
            }
            return;
          }
          if (url === "/snapshot") {
            if (!latest) { res.writeHead(503); res.end("no frame yet"); return; }
            res.writeHead(200, { "content-type": "image/jpeg" });
            res.end(latest);
            return;
          }
          if (url === "/status") {
            const curSession = hub.getSession(a.sessionId);
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ url: curSession.page.url(), alive: !curSession.page.isClosed(), fps: subscribers.size ? 10 : 0 }));
            return;
          }
          if (url === "/click" && req.method === "POST") {
            let body = ""; for await (const c of req) body += c;
            try { const { x, y } = JSON.parse(body); await hub.getSession(a.sessionId).page.mouse.click(x, y); } catch { /* pumppet */ }
            res.writeHead(200); res.end("ok"); return;
          }
          if (url === "/key" && req.method === "POST") {
            let body = ""; for await (const c of req) body += c;
            try { const { key } = JSON.parse(body); await hub.getSession(a.sessionId).page.keyboard.press(key); } catch { /* pumppet */ }
            res.writeHead(200); res.end("ok"); return;
          }
          res.writeHead(404); res.end();
        } catch (e: any) { try { res.writeHead(500); res.end(e.message); } catch {} }
      });
      await new Promise<void>((resolve) => server.listen(a.port ?? 0, "127.0.0.1", resolve));
      const port = (server.address() as any).port;

      views.set(s.id, { server, port, cdp, subscribers, latest, wsSubscribers: new Set() });
      return ok({ url: `http://127.0.0.1:${port}/`, port, note: "open this URL in your browser to watch the session live" });
    },
  },
  {
    name: "liveview_stop",
    description: "Stop the live-view HTTP server for a session.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const v = views.get(s.id);
      if (!v) return ok("not running");
      try { await v.cdp.send("Page.stopScreencast"); } catch { /* pumppet */ }
      try { await v.cdp.detach(); } catch { /* pumppet */ }
      for (const res of v.subscribers) try { res.end(); } catch {}
      await new Promise<void>((resolve) => v.server.close(() => resolve()));
      views.delete(s.id);
      return ok("stopped");
    },
  },
  {
    name: "liveview_status",
    description: "List running live-view servers and their URLs.",
    schema: z.object({}),
    handler: async () => ok(Array.from(views.entries()).map(([sid, v]) => ({ sessionId: sid, url: `http://127.0.0.1:${v.port}/`, viewers: v.subscribers.size }))),
  },
];
