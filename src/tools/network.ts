import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

export const networkTools: ToolDef[] = [
  {
    name: "network_start_recording",
    description: "Begin recording network traffic in the session (on by default).",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => { hub.getSession(a.sessionId).recording = true; return ok("recording"); },
  },
  {
    name: "network_stop_recording",
    description: "Stop recording network traffic.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => { hub.getSession(a.sessionId).recording = false; return ok("stopped"); },
  },
  {
    name: "network_clear",
    description: "Drop the captured request log.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      s.requests.length = 0;
      s.pendingStarts.clear();
      return ok("cleared");
    },
  },
  {
    name: "network_list_requests",
    description: "List captured requests. Filter by host, method, status, resourceType, URL regex.",
    schema: z.object({
      urlPattern: z.string().optional().describe("regex matched against URL"),
      method: z.string().optional(),
      status: z.number().int().optional(),
      resourceType: z.string().optional(),
      limit: z.number().int().positive().optional(),
      includeBodies: z.boolean().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      let re: RegExp | null = null;
      if (a.urlPattern) re = new RegExp(a.urlPattern, "i");
      let items = s.requests.filter((r) => {
        if (re && !re.test(r.url)) return false;
        if (a.method && r.method.toUpperCase() !== a.method.toUpperCase()) return false;
        if (a.status !== undefined && r.status !== a.status) return false;
        if (a.resourceType && r.resourceType !== a.resourceType) return false;
        return true;
      });
      if (a.limit) items = items.slice(-a.limit);
      if (!a.includeBodies) {
        items = items.map((r) => ({ ...r, responseBodySnippet: r.responseBodySnippet ? `[omitted ${r.responseBodySnippet.length}b]` : null }));
      }
      return ok(items);
    },
  },
  {
    name: "network_get_request",
    description: "Full detail for one captured request by id.",
    schema: z.object({ id: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = s.requests.find((x) => x.id === a.id);
      return r ? ok(r) : err(`no request with id ${a.id}`);
    },
  },
  {
    name: "network_replay_request",
    description: "Replay a captured request, optionally overriding method/url/headers/body. Uses the session's APIRequestContext so cookies tag along.",
    schema: z.object({
      id: z.string().optional(),
      url: z.string().url().optional(),
      method: z.string().optional(),
      headers: z.record(z.string()).optional(),
      body: z.string().optional(),
      queryOverrides: z.record(z.string()).optional(),
      includeResponseBody: z.boolean().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      let url: string;
      let method: string;
      let headers: Record<string, string>;
      let body: string | undefined;

      if (a.id) {
        const r = s.requests.find((x) => x.id === a.id);
        if (!r) return err(`no request ${a.id}`);
        url = a.url ?? r.url;
        method = (a.method ?? r.method).toUpperCase();
        headers = { ...r.headers, ...(a.headers ?? {}) };
        body = a.body ?? r.postData ?? undefined;
      } else {
        if (!a.url) return err("either id or url required");
        url = a.url;
        method = (a.method ?? "GET").toUpperCase();
        headers = a.headers ?? {};
        body = a.body;
      }

      if (a.queryOverrides) {
        const u = new URL(url);
        for (const [k, v] of Object.entries(a.queryOverrides as Record<string, string>)) u.searchParams.set(k, v);
        url = u.toString();
      }
      // Playwright doesn't allow some headers; strip hop-by-hop
      for (const h of ["host", "content-length", "connection", "accept-encoding", ":authority", ":method", ":path", ":scheme"]) {
        delete headers[h];
        delete headers[h.toLowerCase()];
      }

      const t0 = Date.now();
      try {
        const resp = await s.context.request.fetch(url, {
          method,
          headers,
          data: body,
          ignoreHTTPSErrors: true,
          maxRedirects: 0,
        });
        const dt = Date.now() - t0;
        const respHeaders = await resp.headersArray();
        let bodyOut: string | null = null;
        if (a.includeResponseBody !== false) {
          try { bodyOut = (await resp.text()).slice(0, 20000); } catch { bodyOut = "[binary]"; }
        }
        return ok({
          durationMs: dt,
          status: resp.status(),
          statusText: resp.statusText(),
          url: resp.url(),
          headers: respHeaders,
          body: bodyOut,
        });
      } catch (e: any) {
        return err(`replay failed: ${e?.message ?? e}`);
      }
    },
  },
  {
    name: "network_fuzz_param",
    description: "Replay a request many times, substituting one query/body/header parameter from a list of payloads. Returns a diff table of status, length, response time.",
    schema: z.object({
      id: z.string().optional(),
      url: z.string().url().optional(),
      method: z.string().optional(),
      headers: z.record(z.string()).optional(),
      body: z.string().optional(),
      paramLocation: z.enum(["query", "body-form", "body-json", "header", "path"]),
      paramName: z.string(),
      payloads: z.array(z.string()).min(1),
      concurrency: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      let baseUrl: string;
      let method: string;
      let headers: Record<string, string>;
      let body: string | undefined;
      if (a.id) {
        const r = s.requests.find((x) => x.id === a.id);
        if (!r) return err(`no request ${a.id}`);
        baseUrl = a.url ?? r.url;
        method = (a.method ?? r.method).toUpperCase();
        headers = { ...r.headers, ...(a.headers ?? {}) };
        body = a.body ?? r.postData ?? undefined;
      } else {
        if (!a.url) return err("id or url required");
        baseUrl = a.url;
        method = (a.method ?? "GET").toUpperCase();
        headers = a.headers ?? {};
        body = a.body;
      }
      for (const h of ["host", "content-length", "connection", "accept-encoding"]) delete headers[h];

      const concurrency = Math.min(a.concurrency ?? 4, 10);
      const results: any[] = [];
      let idx = 0;
      const payloads = a.payloads;

      const worker = async () => {
        while (idx < payloads.length) {
          const myIdx = idx++;
          const payload = payloads[myIdx];
          let url = baseUrl;
          let bodyMut = body;
          const headersMut = { ...headers };
          if (a.paramLocation === "query") {
            const u = new URL(url); u.searchParams.set(a.paramName, payload); url = u.toString();
          } else if (a.paramLocation === "path") {
            url = url.replace(`{${a.paramName}}`, encodeURIComponent(payload));
          } else if (a.paramLocation === "header") {
            headersMut[a.paramName] = payload;
          } else if (a.paramLocation === "body-form") {
            const p = new URLSearchParams(String(bodyMut ?? "")); p.set(a.paramName, payload); bodyMut = p.toString();
            headersMut["content-type"] = headersMut["content-type"] ?? "application/x-www-form-urlencoded";
          } else if (a.paramLocation === "body-json") {
            try {
              const o = JSON.parse(bodyMut ?? "{}"); o[a.paramName] = payload; bodyMut = JSON.stringify(o);
              headersMut["content-type"] = headersMut["content-type"] ?? "application/json";
            } catch { bodyMut = JSON.stringify({ [a.paramName]: payload }); }
          }
          const t0 = Date.now();
          try {
            const resp = await s.context.request.fetch(url, { method, headers: headersMut, data: bodyMut, ignoreHTTPSErrors: true, maxRedirects: 0 });
            const text = await resp.text().catch(() => "");
            results[myIdx] = {
              payload, status: resp.status(), length: text.length,
              durationMs: Date.now() - t0,
              reflected: text.includes(payload),
              snippet: text.slice(0, 400),
            };
          } catch (e: any) {
            results[myIdx] = { payload, error: e?.message ?? String(e), durationMs: Date.now() - t0 };
          }
        }
      };
      await Promise.all(Array.from({ length: concurrency }, () => worker()));
      return ok({ count: results.length, results });
    },
  },
  {
    name: "network_curl",
    description: "Export a captured request as a curl command (for sharing or external replay).",
    schema: z.object({ id: z.string(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const r = s.requests.find((x) => x.id === a.id);
      if (!r) return err(`no request ${a.id}`);
      const parts = [`curl -i -X ${r.method} ${JSON.stringify(r.url)}`];
      for (const [k, v] of Object.entries(r.headers)) {
        if (k.startsWith(":")) continue;
        parts.push(`-H ${JSON.stringify(`${k}: ${v}`)}`);
      }
      if (r.postData) parts.push(`--data-binary ${JSON.stringify(r.postData)}`);
      return ok(parts.join(" \\\n  "));
    },
  },
  {
    name: "network_har_export",
    description: "Return captured requests as a HAR 1.2 archive JSON.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const entries = s.requests.map((r) => ({
        startedDateTime: new Date(r.ts).toISOString(),
        time: r.durationMs ?? 0,
        request: {
          method: r.method, url: r.url, httpVersion: "HTTP/1.1",
          headers: Object.entries(r.headers).map(([n, v]) => ({ name: n, value: v })),
          queryString: [], cookies: [],
          headersSize: -1, bodySize: r.postData ? r.postData.length : 0,
          postData: r.postData ? { mimeType: r.headers["content-type"] ?? "", text: r.postData } : undefined,
        },
        response: {
          status: r.status ?? 0, statusText: "", httpVersion: "HTTP/1.1",
          headers: Object.entries(r.responseHeaders ?? {}).map(([n, v]) => ({ name: n, value: v })),
          cookies: [], content: { size: r.responseBodySnippet?.length ?? 0, mimeType: r.responseHeaders?.["content-type"] ?? "", text: r.responseBodySnippet ?? "" },
          redirectURL: r.responseHeaders?.["location"] ?? "",
          headersSize: -1, bodySize: r.responseBodySnippet?.length ?? 0,
        },
        cache: {},
        timings: { send: 0, wait: r.durationMs ?? 0, receive: 0 },
      }));
      return ok({ log: { version: "1.2", creator: { name: "browser-mcp", version: "0.1" }, entries } });
    },
  },
];
