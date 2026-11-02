import { z } from "zod";
import { createHash, createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { ToolDef, ok, err } from "../types.js";

const TOP_PWS = ["123456","password","12345678","qwerty","123456789","12345","1234","111111","1234567","dragon","123123","baseball","abc123","football","monkey","letmein","696969","shadow","master","666666","qwertyuiop","123321","mustang","1234567890","michael","654321","pussy","superman","1qaz2wsx","7777777","fuckyou","121212","000000","qazwsx","123qwe","killer","trustno1","jordan","jennifer","zxcvbnm","asdfgh","hunter","buster","soccer","harley","batman","andrew","tigger","sunshine","iloveyou","2000","charlie","robert","thomas","hockey","ranger","daniel","starwars","klaster","112233","george","asshole","computer","michelle","jessica","pepper","1111","zxcvbn","555555","11111111","131313","freedom","777777","pass","maggie","159753","aaaaaa","ginger","princess","joshua","cheese","amanda","summer","love","ashley","6969","nicole","chelsea","biteme","matthew","access","yankees","987654321","dallas","austin","thunder","taylor","matrix","mobilemail","mom","monitor","monitoring","montana","moon","moscow"];

const HASH_SHAPES: Array<{ len: number; name: string; algo?: string }> = [
  { len: 32, name: "MD5", algo: "md5" }, { len: 40, name: "SHA-1", algo: "sha1" },
  { len: 56, name: "SHA-224", algo: "sha224" }, { len: 64, name: "SHA-256", algo: "sha256" },
  { len: 96, name: "SHA-384", algo: "sha384" }, { len: 128, name: "SHA-512", algo: "sha512" },
  { len: 60, name: "bcrypt (if starts $2a$/$2b$/$2y$)" },
  { len: 128, name: "Whirlpool" },
];

export const cryptoTools: ToolDef[] = [
  {
    name: "codec_multi",
    description: "Encode or decode a string with many codecs: base64, base64url, hex, url, url-double, html-entities, unicode-escape, utf-16-le.",
    schema: z.object({
      op: z.enum(["encode", "decode"]),
      codec: z.enum(["base64", "base64url", "hex", "url", "url-double", "html-entities", "unicode-escape", "utf-16-le"]),
      input: z.string(),
    }),
    handler: async (a) => {
      try {
        if (a.op === "encode") {
          switch (a.codec) {
            case "base64": return ok(Buffer.from(a.input, "utf8").toString("base64"));
            case "base64url": return ok(Buffer.from(a.input, "utf8").toString("base64url"));
            case "hex": return ok(Buffer.from(a.input, "utf8").toString("hex"));
            case "url": return ok(encodeURIComponent(a.input));
            case "url-double": return ok(encodeURIComponent(encodeURIComponent(a.input)));
            case "html-entities": return ok(a.input.replace(/[<>&"']/g, (c: string) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" } as any)[c]));
            case "unicode-escape": return ok([...a.input].map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join(""));
            case "utf-16-le": return ok(Buffer.from(a.input, "utf16le").toString("hex"));
          }
        } else {
          switch (a.codec) {
            case "base64": return ok(Buffer.from(a.input, "base64").toString("utf8"));
            case "base64url": return ok(Buffer.from(a.input.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
            case "hex": return ok(Buffer.from(a.input, "hex").toString("utf8"));
            case "url": return ok(decodeURIComponent(a.input));
            case "url-double": return ok(decodeURIComponent(decodeURIComponent(a.input)));
            case "html-entities": return ok(a.input.replace(/&(lt|gt|amp|quot|#39|#(\d+)|#x([0-9a-f]+));/gi, (_m: string, n: string, dec: string, hex: string) => dec ? String.fromCharCode(+dec) : hex ? String.fromCharCode(parseInt(hex, 16)) : ({ lt: "<", gt: ">", amp: "&", quot: '"', "#39": "'" } as any)[n]));
            case "unicode-escape": return ok(a.input.replace(/\\u([0-9a-f]{4})/gi, (_m: string, h: string) => String.fromCharCode(parseInt(h, 16))));
            case "utf-16-le": return ok(Buffer.from(a.input, "hex").toString("utf16le"));
          }
        }
      } catch (e: any) { return err(e.message); }
      return err("unreachable");
    },
  },
  {
    name: "crypto_xor",
    description: "XOR two strings (both utf-8 or both hex) and return the result as hex.",
    schema: z.object({ a: z.string(), b: z.string(), format: z.enum(["utf8", "hex"]).optional() }),
    handler: async (a) => {
      const fmt = a.format ?? "utf8";
      const A = fmt === "hex" ? Buffer.from(a.a, "hex") : Buffer.from(a.a, "utf8");
      const B = fmt === "hex" ? Buffer.from(a.b, "hex") : Buffer.from(a.b, "utf8");
      const out = Buffer.alloc(Math.max(A.length, B.length));
      for (let i = 0; i < out.length; i++) out[i] = (A[i % A.length] ?? 0) ^ (B[i % B.length] ?? 0);
      return ok({ hex: out.toString("hex"), utf8: out.toString("utf8") });
    },
  },
  {
    name: "crypto_rot",
    description: "Caesar cipher / rot-N on a string. rot13 is the common one.",
    schema: z.object({ input: z.string(), shift: z.number().int().optional() }),
    handler: async (a) => {
      const n = ((a.shift ?? 13) % 26 + 26) % 26;
      const out = [...a.input].map((c) => {
        const code = c.charCodeAt(0);
        if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + n) % 26) + 65);
        if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + n) % 26) + 97);
        return c;
      }).join("");
      return ok(out);
    },
  },
  {
    name: "crypto_aes",
    description: "AES-256-GCM encrypt or decrypt. Pass base64 of ciphertext for decrypt (format: nonce|ciphertext|tag).",
    schema: z.object({ op: z.enum(["encrypt", "decrypt"]), password: z.string(), input: z.string() }),
    handler: async (a) => {
      try {
        const key = scryptSync(a.password, "browser-mcp-salt", 32);
        if (a.op === "encrypt") {
          const iv = randomBytes(12);
          const cipher = createCipheriv("aes-256-gcm", key, iv);
          const ct = Buffer.concat([cipher.update(a.input, "utf8"), cipher.final()]);
          const tag = cipher.getAuthTag();
          return ok(Buffer.concat([iv, ct, tag]).toString("base64"));
        } else {
          const buf = Buffer.from(a.input, "base64");
          const iv = buf.subarray(0, 12);
          const tag = buf.subarray(buf.length - 16);
          const ct = buf.subarray(12, buf.length - 16);
          const dec = createDecipheriv("aes-256-gcm", key, iv);
          dec.setAuthTag(tag);
          const pt = Buffer.concat([dec.update(ct), dec.final()]);
          return ok(pt.toString("utf8"));
        }
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "hash_identify",
    description: "Guess the hash algorithm by shape. Supports MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512, bcrypt, argon2, MySQL5, NTLM, scrypt.",
    schema: z.object({ hash: z.string() }),
    handler: async (a) => {
      const h = a.hash.trim();
      const options: string[] = [];
      if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(h)) options.push("bcrypt");
      if (/^\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$/.test(h)) options.push("argon2");
      if (/^\$scrypt\$|^\$7\$/.test(h)) options.push("scrypt");
      if (/^\$1\$/.test(h)) options.push("md5crypt");
      if (/^\$5\$/.test(h)) options.push("sha256crypt");
      if (/^\$6\$/.test(h)) options.push("sha512crypt");
      if (/^\*[A-F0-9]{40}$/i.test(h)) options.push("MySQL5");
      if (/^[a-f0-9]{32}$/i.test(h)) options.push("MD5", "NTLM", "MD4");
      if (/^[a-f0-9]{40}$/i.test(h)) options.push("SHA-1", "MySQL SHA-1");
      if (/^[a-f0-9]{56}$/i.test(h)) options.push("SHA-224");
      if (/^[a-f0-9]{64}$/i.test(h)) options.push("SHA-256", "SHA-3-256", "BLAKE2s");
      if (/^[a-f0-9]{96}$/i.test(h)) options.push("SHA-384");
      if (/^[a-f0-9]{128}$/i.test(h)) options.push("SHA-512", "SHA-3-512", "BLAKE2b", "Whirlpool");
      if (/^[A-Za-z0-9+/=]{27,}$/.test(h) && !options.length) options.push("base64 (unknown hash)");
      return ok({ candidates: options, length: h.length });
    },
  },
  {
    name: "hash_crack_dict",
    description: "Try a wordlist against a hash. Supports md5/sha1/sha256/sha512. Also recognizes bcrypt but doesn't crack it.",
    schema: z.object({
      hash: z.string(),
      algo: z.enum(["md5", "sha1", "sha256", "sha512"]).optional().describe("auto-detected from length if omitted"),
      wordlist: z.array(z.string()).optional().describe("defaults to top-100 passwords"),
      max: z.number().int().positive().optional(),
    }),
    handler: async (a) => {
      const h = a.hash.toLowerCase().trim();
      const algo = a.algo ?? (h.length === 32 ? "md5" : h.length === 40 ? "sha1" : h.length === 64 ? "sha256" : h.length === 128 ? "sha512" : null);
      if (!algo) return err("could not auto-detect algo; pass algo");
      const words = a.wordlist ?? TOP_PWS;
      const max = Math.min(a.max ?? 2000, words.length);
      for (let i = 0; i < max; i++) {
        if (createHash(algo).update(words[i]).digest("hex") === h) return ok({ cracked: true, algo, password: words[i], triedUpTo: i + 1 });
      }
      return ok({ cracked: false, algo, triedUpTo: max });
    },
  },
  {
    name: "password_strength",
    description: "Score a password's strength (0-4) with reasoning. Flags common passwords, dictionary words, repeated chars, keyboard patterns.",
    schema: z.object({ password: z.string() }),
    handler: async (a) => {
      const p = a.password;
      const issues: string[] = []; let score = 0;
      if (p.length >= 8) score++; else issues.push("<8 chars");
      if (p.length >= 12) score++; else if (p.length >= 8) issues.push("<12 chars (recommended)");
      if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++; else issues.push("no mixed case");
      if (/\d/.test(p)) score++; else issues.push("no digit");
      if (/[^A-Za-z0-9]/.test(p)) score++; else issues.push("no symbol");
      if (TOP_PWS.includes(p.toLowerCase())) { score = 0; issues.push("in top-100 common passwords"); }
      if (/^(.)\1{3,}$/.test(p)) issues.push("same char repeated");
      if (/qwerty|asdf|1234|abcd|password|admin|letmein/i.test(p)) { score = Math.max(0, score - 2); issues.push("contains keyboard/common pattern"); }
      const final = Math.min(4, Math.max(0, Math.round(score / 5 * 4)));
      return ok({ score: final, scaleMax: 4, length: p.length, issues });
    },
  },
  {
    name: "password_in_top",
    description: "Is this password in the top-100 most-common list? Fast check for 'is this absolute junk'.",
    schema: z.object({ password: z.string() }),
    handler: async (a) => ok({ common: TOP_PWS.includes(a.password.toLowerCase()) }),
  },
];
