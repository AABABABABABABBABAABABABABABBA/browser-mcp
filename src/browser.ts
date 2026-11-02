import { chromium, Browser, BrowserContext, Page, Request, Response } from "playwright";
import { randomUUID } from "node:crypto";

export interface CapturedRequest {
  id: string;
  ts: number;
  method: string;
  url: string;
  resourceType: string;
  headers: Record<string, string>;
  postData: string | null;
  status: number | null;
  responseHeaders: Record<string, string> | null;
  responseBodySnippet: string | null;
  fromCache: boolean;
  durationMs: number | null;
  failure: string | null;
}

export interface ConsoleEntry {
  ts: number;
  type: string;
  text: string;
  location?: { url: string; line: number; column: number };
}

export interface Session {
  id: string;
  context: BrowserContext;
  page: Page;
  requests: CapturedRequest[];
  pendingStarts: Map<string, number>;
  consoleLogs: ConsoleEntry[];
  pageErrors: Array<{ ts: number; message: string; stack?: string }>;
  recording: boolean;
  createdAt: number;
}

const BROWSER_EXECUTABLE = "/opt/pw-browsers/chromium";

export class BrowserHub {
  private browser: Browser | null = null;
  private sessions = new Map<string, Session>();
  private defaultSessionId: string | null = null;

  async getBrowser(): Promise<Browser> {
    if (this.browser && this.browser.isConnected()) return this.browser;
    const launchOpts: Parameters<typeof chromium.launch>[0] = {
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    };
    try {
      this.browser = await chromium.launch(launchOpts);
    } catch {
      this.browser = await chromium.launch({ ...launchOpts, executablePath: BROWSER_EXECUTABLE });
    }
    return this.browser;
  }

  async openSession(opts: {
    userAgent?: string;
    viewport?: { width: number; height: number };
    extraHeaders?: Record<string, string>;
    ignoreHttpsErrors?: boolean;
    proxy?: string;
  } = {}): Promise<Session> {
    const browser = await this.getBrowser();
    const context = await browser.newContext({
      userAgent: opts.userAgent,
      viewport: opts.viewport ?? { width: 1366, height: 850 },
      extraHTTPHeaders: opts.extraHeaders,
      ignoreHTTPSErrors: opts.ignoreHttpsErrors ?? true,
      proxy: opts.proxy ? { server: opts.proxy } : undefined,
    });
    const page = await context.newPage();
    const session: Session = {
      id: randomUUID().slice(0, 8),
      context,
      page,
      requests: [],
      pendingStarts: new Map(),
      consoleLogs: [],
      pageErrors: [],
      recording: true,
      createdAt: Date.now(),
    };
    this.wireNetworkCapture(session);
    this.wirePageCapture(session);
    this.sessions.set(session.id, session);
    if (!this.defaultSessionId) this.defaultSessionId = session.id;
    return session;
  }

  private wireNetworkCapture(session: Session) {
    const headerObj = (h: Record<string, string>) => ({ ...h });

    session.context.on("request", (req: Request) => {
      if (!session.recording) return;
      const id = randomUUID().slice(0, 8);
      (req as any).__id = id;
      session.pendingStarts.set(id, Date.now());
      session.requests.push({
        id,
        ts: Date.now(),
        method: req.method(),
        url: req.url(),
        resourceType: req.resourceType(),
        headers: headerObj(req.headers()),
        postData: req.postData(),
        status: null,
        responseHeaders: null,
        responseBodySnippet: null,
        fromCache: false,
        durationMs: null,
        failure: null,
      });
      if (session.requests.length > 2000) session.requests.splice(0, 500);
    });

    session.context.on("response", async (res: Response) => {
      if (!session.recording) return;
      const req = res.request();
      const id = (req as any).__id as string | undefined;
      if (!id) return;
      const entry = session.requests.find((r) => r.id === id);
      if (!entry) return;
      entry.status = res.status();
      try {
        entry.responseHeaders = headerObj(await res.allHeaders());
      } catch {
        entry.responseHeaders = headerObj(res.headers());
      }
      try {
        const ct = (entry.responseHeaders?.["content-type"] ?? "").toLowerCase();
        if (
          ct.includes("text") ||
          ct.includes("json") ||
          ct.includes("xml") ||
          ct.includes("javascript") ||
          ct.includes("html")
        ) {
          const body = await res.text();
          entry.responseBodySnippet = body.slice(0, 8000);
        } else {
          entry.responseBodySnippet = `[binary ${ct || "unknown"}]`;
        }
      } catch (e: any) {
        entry.responseBodySnippet = `[body-unavailable: ${e?.message ?? e}]`;
      }
      entry.fromCache = res.fromServiceWorker() || (res.headers()["x-cache"] ?? "").toLowerCase().includes("hit");
      const start = session.pendingStarts.get(id);
      if (start) entry.durationMs = Date.now() - start;
    });

    session.context.on("requestfailed", (req: Request) => {
      if (!session.recording) return;
      const id = (req as any).__id as string | undefined;
      if (!id) return;
      const entry = session.requests.find((r) => r.id === id);
      if (entry) entry.failure = req.failure()?.errorText ?? "failed";
    });
  }

  private wirePageCapture(session: Session) {
    const attach = (page: Page) => {
      page.on("console", (msg) => {
        const loc = msg.location();
        session.consoleLogs.push({
          ts: Date.now(),
          type: msg.type(),
          text: msg.text(),
          location: loc.url ? { url: loc.url, line: loc.lineNumber, column: loc.columnNumber } : undefined,
        });
        if (session.consoleLogs.length > 1000) session.consoleLogs.splice(0, 300);
      });
      page.on("pageerror", (err) => {
        session.pageErrors.push({ ts: Date.now(), message: err.message, stack: err.stack });
        if (session.pageErrors.length > 500) session.pageErrors.splice(0, 150);
      });
      page.on("dialog", async (dialog) => {
        session.consoleLogs.push({
          ts: Date.now(),
          type: `dialog:${dialog.type()}`,
          text: dialog.message(),
        });
        try { await dialog.dismiss(); } catch { /* pumppet */ }
      });
    };
    attach(session.page);
    session.context.on("page", (p) => attach(p));
  }

  getSession(id?: string): Session {
    const sid = id ?? this.defaultSessionId;
    if (!sid) throw new Error("no browser session open — call browser_open first");
    const s = this.sessions.get(sid);
    if (!s) throw new Error(`session ${sid} not found`);
    return s;
  }

  listSessions() {
    return Array.from(this.sessions.values()).map((s) => ({
      id: s.id,
      url: s.page.url(),
      createdAt: s.createdAt,
      requestCount: s.requests.length,
      recording: s.recording,
      isDefault: s.id === this.defaultSessionId,
    }));
  }

  async closeSession(id?: string) {
    const s = this.getSession(id);
    await s.context.close();
    this.sessions.delete(s.id);
    if (this.defaultSessionId === s.id) {
      this.defaultSessionId = this.sessions.keys().next().value ?? null;
    }
  }

  async shutdown() {
    for (const s of this.sessions.values()) {
      try { await s.context.close(); } catch { /* pumppet */ }
    }
    this.sessions.clear();
    if (this.browser) {
      try { await this.browser.close(); } catch { /* pumppet */ }
      this.browser = null;
    }
  }
}

export const hub = new BrowserHub();
