import { z } from "zod";
import { createHmac, randomBytes } from "node:crypto";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

function b64url(b: Buffer): string { return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }

function parseSetCookie(header: string) {
  const parts = header.split(/;\s*/);
  const first = parts.shift() ?? "";
  const [name, ...rest] = first.split("=");
  const value = rest.join("=");
  const out: any = { name: name.trim(), value };
  for (const p of parts) {
    const [k, v] = p.split("=");
    const kl = k.toLowerCase().trim();
    if (kl === "secure") out.secure = true;
    else if (kl === "httponly") out.httpOnly = true;
    else if (kl === "samesite") out.sameSite = (v ?? "").trim();
    else if (kl === "path") out.path = v;
    else if (kl === "domain") out.domain = v;
    else if (kl === "max-age") out.maxAge = Number(v);
    else if (kl === "expires") out.expires = v;
  }
  return out;
}

export const cookieTools: ToolDef[] = [
  {
    name: "cookie_list",
    description: "List cookies in the current browser session. Filter by domain or name.",
    schema: z.object({
      domainContains: z.string().optional(),
      nameContains: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      let cookies = await s.context.cookies();
      if (a.domainContains) cookies = cookies.filter((c) => c.domain.includes(a.domainContains!));
      if (a.nameContains) cookies = cookies.filter((c) => c.name.includes(a.nameContains!));
      return ok(cookies);
    },
  },
  {
    name: "cookie_set",
    description: "Set one or more cookies in the session. Each cookie needs a name+value plus either domain+path or url.",
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
        expires: z.number().optional(),
      })),
      ...sessionArg,
    }),
    handler: async (a) => {
      await hub.getSession(a.sessionId).context.addCookies(a.cookies as any);
      return ok({ set: a.cookies.length });
    },
  },
  {
    name: "cookie_delete",
    description: "Delete a single cookie by name (and optional domain match), or clear all cookies for the session.",
    schema: z.object({ name: z.string().optional(), domainContains: z.string().optional(), clearAll: z.boolean().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      if (a.clearAll) { await s.context.clearCookies(); return ok("all cleared"); }
      if (!a.name) return err("provide name OR clearAll:true");
      const keep = (await s.context.cookies()).filter((c) => c.name !== a.name || (a.domainContains && !c.domain.includes(a.domainContains)));
      await s.context.clearCookies();
      await s.context.addCookies(keep as any);
      return ok("deleted");
    },
  },
  {
    name: "cookie_parse_set_cookie",
    description: "Parse a Set-Cookie response header (or multiple, newline-separated) into structured records.",
    schema: z.object({ header: z.string() }),
    handler: async (a) => {
      const headers = a.header.split(/\n|,(?=[^ ,]+=)/).map((h: string) => h.trim()).filter(Boolean);
      return ok(headers.map(parseSetCookie));
    },
  },
  {
    name: "cookie_header_from_jar",
    description: "Build a single `Cookie: a=b; c=d` request header string from the session's cookies, optionally filtered by domain.",
    schema: z.object({ domainContains: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      let cookies = await s.context.cookies();
      if (a.domainContains) cookies = cookies.filter((c) => c.domain.includes(a.domainContains!));
      return ok(cookies.map((c) => `${c.name}=${c.value}`).join("; "));
    },
  },
  {
    name: "cookie_header_parse",
    description: "Parse a browser `Cookie: a=b; c=d` request-header string into { name: value }.",
    schema: z.object({ cookieHeader: z.string() }),
    handler: async (a) => {
      const out: Record<string, string> = {};
      for (const kv of a.cookieHeader.split(/;\s*/)) {
        const i = kv.indexOf("=");
        if (i < 0) continue;
        out[kv.slice(0, i).trim()] = kv.slice(i + 1);
      }
      return ok(out);
    },
  },
  {
    name: "cookie_generate",
    description: "Generate plausible session-cookie values. Shapes: hex (32B), uuid, base64url, numeric, laravel-style, PHPSESSID, Flask-signed-style.",
    schema: z.object({
      shape: z.enum(["hex", "uuid", "base64url", "numeric", "laravel", "phpsessid", "flask", "jwt-null"]),
      length: z.number().int().positive().optional(),
      count: z.number().int().min(1).max(50).optional(),
    }),
    handler: async (a) => {
      const n = a.count ?? 1;
      const out: string[] = [];
      for (let i = 0; i < n; i++) {
        const len = a.length ?? 32;
        switch (a.shape) {
          case "hex": out.push(randomBytes(len).toString("hex").slice(0, len)); break;
          case "uuid": {
            const b = randomBytes(16); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
            const h = b.toString("hex");
            out.push(`${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`);
            break;
          }
          case "base64url": out.push(b64url(randomBytes(len))); break;
          case "numeric": out.push(Array.from({ length: len }, () => Math.floor(Math.random() * 10)).join("")); break;
          case "laravel": {
            const payload = { iv: b64url(randomBytes(16)), value: b64url(randomBytes(32)), mac: randomBytes(32).toString("hex") };
            out.push(Buffer.from(JSON.stringify(payload)).toString("base64"));
            break;
          }
          case "phpsessid": out.push(randomBytes(13).toString("hex").slice(0, 26)); break;
          case "flask": {
            const data = b64url(Buffer.from(JSON.stringify({ user: null, _fresh: true })));
            const ts = b64url(Buffer.from(Date.now().toString()));
            const sig = b64url(randomBytes(32));
            out.push(`${data}.${ts}.${sig}`);
            break;
          }
          case "jwt-null": {
            const h = b64url(Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })));
            const p = b64url(Buffer.from(JSON.stringify({ sub: "test", iat: Math.floor(Date.now() / 1000) })));
            out.push(`${h}.${p}.`);
            break;
          }
        }
      }
      return ok(n === 1 ? out[0] : out);
    },
  },
  {
    name: "jwt_build",
    description: "Build a JWT. If secret is given, signs HS256; otherwise emits alg=none (useful for probing alg confusion).",
    schema: z.object({
      payload: z.record(z.any()),
      secret: z.string().optional(),
      alg: z.enum(["HS256", "HS384", "HS512", "none"]).optional(),
      extraHeader: z.record(z.any()).optional(),
    }),
    handler: async (a) => {
      const alg = a.alg ?? (a.secret ? "HS256" : "none");
      const header = { alg, typ: "JWT", ...(a.extraHeader ?? {}) };
      const h = b64url(Buffer.from(JSON.stringify(header)));
      const p = b64url(Buffer.from(JSON.stringify(a.payload)));
      if (alg === "none") return ok(`${h}.${p}.`);
      if (!a.secret) return err("secret required for HS*");
      const hashAlg = alg === "HS256" ? "sha256" : alg === "HS384" ? "sha384" : "sha512";
      const sig = b64url(createHmac(hashAlg, a.secret).update(`${h}.${p}`).digest());
      return ok(`${h}.${p}.${sig}`);
    },
  },
  {
    name: "jwt_verify_hs",
    description: "Verify a JWT's HMAC signature with a candidate secret. Returns {valid, payload} or {valid:false}.",
    schema: z.object({ token: z.string(), secret: z.string() }),
    handler: async (a) => {
      const parts = a.token.split(".");
      if (parts.length !== 3) return err("not a JWT");
      let header; try { header = JSON.parse(Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")); } catch { return err("bad header"); }
      const alg = header.alg?.toUpperCase?.();
      if (!["HS256", "HS384", "HS512"].includes(alg)) return ok({ valid: false, reason: `alg=${alg}` });
      const hashAlg = alg === "HS256" ? "sha256" : alg === "HS384" ? "sha384" : "sha512";
      const expected = b64url(createHmac(hashAlg, a.secret).update(`${parts[0]}.${parts[1]}`).digest());
      const valid = expected === parts[2];
      if (!valid) return ok({ valid: false });
      const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
      return ok({ valid: true, header, payload });
    },
  },
  {
    name: "jwt_crack_hs",
    description: "Try a list of candidate secrets against a JWT (HMAC algs). Stops on first hit. Keep lists small (default max 2000).",
    schema: z.object({ token: z.string(), wordlist: z.array(z.string()).min(1), max: z.number().int().positive().optional() }),
    handler: async (a) => {
      const parts = a.token.split("."); if (parts.length !== 3) return err("not a JWT");
      let header; try { header = JSON.parse(Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")); } catch { return err("bad header"); }
      const alg = header.alg?.toUpperCase?.();
      if (!["HS256", "HS384", "HS512"].includes(alg)) return ok({ cracked: false, reason: `alg=${alg}` });
      const hashAlg = alg === "HS256" ? "sha256" : alg === "HS384" ? "sha384" : "sha512";
      const max = Math.min(a.max ?? 2000, a.wordlist.length);
      for (let i = 0; i < max; i++) {
        const w = a.wordlist[i];
        const sig = b64url(createHmac(hashAlg, w).update(`${parts[0]}.${parts[1]}`).digest());
        if (sig === parts[2]) return ok({ cracked: true, secret: w, triedUpTo: i + 1 });
      }
      return ok({ cracked: false, triedUpTo: max });
    },
  },
];
