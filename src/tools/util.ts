import { z } from "zod";
import { createHash } from "node:crypto";
import { ToolDef, ok, err } from "../types.js";
import { hub } from "../browser.js";

export const utilTools: ToolDef[] = [
  {
    name: "http_request",
    description: "Raw HTTP request through the session's APIRequestContext (shares cookies with the browser).",
    schema: z.object({
      url: z.string().url(),
      method: z.string().optional(),
      headers: z.record(z.string()).optional(),
      body: z.string().optional(),
      followRedirects: z.boolean().optional(),
      sessionId: z.string().optional(),
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const t0 = Date.now();
      const r = await s.context.request.fetch(a.url, {
        method: (a.method ?? "GET").toUpperCase(),
        headers: a.headers,
        data: a.body,
        ignoreHTTPSErrors: true,
        maxRedirects: a.followRedirects === false ? 0 : 20,
      });
      const text = await r.text().catch(() => "");
      return ok({
        status: r.status(), statusText: r.statusText(), url: r.url(),
        durationMs: Date.now() - t0,
        headers: await r.headersArray(),
        body: text.slice(0, 50000),
        truncated: text.length > 50000,
      });
    },
  },
  {
    name: "base64",
    description: "Encode or decode base64.",
    schema: z.object({ op: z.enum(["encode", "decode"]), input: z.string() }),
    handler: async (a) => ok(a.op === "encode" ? Buffer.from(a.input, "utf8").toString("base64") : Buffer.from(a.input, "base64").toString("utf8")),
  },
  {
    name: "url_codec",
    description: "URL encode or decode a string.",
    schema: z.object({ op: z.enum(["encode", "decode"]), input: z.string() }),
    handler: async (a) => {
      try { return ok(a.op === "encode" ? encodeURIComponent(a.input) : decodeURIComponent(a.input)); }
      catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "hash",
    description: "Hash a string (md5, sha1, sha256, sha512).",
    schema: z.object({ algo: z.enum(["md5", "sha1", "sha256", "sha512"]), input: z.string() }),
    handler: async (a) => ok(createHash(a.algo).update(a.input).digest("hex")),
  },
];
