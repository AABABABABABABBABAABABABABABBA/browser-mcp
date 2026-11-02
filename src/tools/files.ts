import { z } from "zod";
import { createHash } from "node:crypto";
import { promises as fs, createWriteStream } from "node:fs";
import { mkdir, writeFile, readFile, stat, readdir } from "node:fs/promises";
import { basename, dirname, extname, join, resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

// -------- magic-byte MIME detection --------
function sniffMime(buf: Buffer): string {
  const h = (n: number) => buf.slice(0, n).toString("hex");
  if (buf.length < 2) return "application/octet-stream";
  const b4 = h(4), b8 = h(8);
  if (b4.startsWith("89504e47")) return "image/png";
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "image/jpeg";
  if (b4 === "47494638") return "image/gif";
  if (buf.slice(0, 4).toString() === "RIFF" && buf.slice(8, 12).toString() === "WEBP") return "image/webp";
  if (b4 === "25504446") return "application/pdf";
  if (b4 === "504b0304" || b4 === "504b0506" || b4 === "504b0708") return "application/zip";
  if (b4 === "1f8b0808" || h(2) === "1f8b") return "application/gzip";
  if (buf.slice(257, 263).toString() === "ustar") return "application/x-tar";
  if (b4 === "7f454c46") return "application/x-elf";
  if (h(2) === "4d5a") return "application/x-msdownload";
  if (buf.slice(0, 4).toString() === "RIFF") return "audio/wav";
  if (b4 === "664c6143") return "audio/flac";
  if (b4.startsWith("fff") || (buf[0] === 0x49 && buf[1] === 0x44 && buf[2] === 0x33)) return "audio/mpeg";
  if (b8.startsWith("00000018") || b8.startsWith("00000020")) { if (buf.slice(4, 8).toString() === "ftyp") return "video/mp4"; }
  const start = buf.slice(0, 2048).toString("utf8");
  if (/^\s*</.test(start) && /<(html|HTML)/.test(start)) return "text/html";
  if (/^\s*</.test(start)) return "application/xml";
  if (/^\s*[\{\[]/.test(start)) return "application/json";
  if (/^#!/.test(start)) return "text/x-shellscript";
  // text if mostly printable
  let printable = 0; for (let i = 0; i < Math.min(buf.length, 1024); i++) if (buf[i] === 9 || buf[i] === 10 || buf[i] === 13 || (buf[i] >= 32 && buf[i] <= 126)) printable++;
  if (printable / Math.min(buf.length, 1024) > 0.9) return "text/plain";
  return "application/octet-stream";
}

// -------- minimal ZIP central-directory reader --------
function readZipCentralDir(buf: Buffer): Array<{ name: string; size: number; compressedSize: number; method: number; offset: number; crc: number }> {
  // Find EOCD (End Of Central Dir) — scan from the end
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a zip (no EOCD)");
  const total = buf.readUInt16LE(eocd + 10);
  let cdOff = buf.readUInt32LE(eocd + 16);
  const entries: any[] = [];
  for (let i = 0; i < total; i++) {
    if (buf.readUInt32LE(cdOff) !== 0x02014b50) break;
    const method = buf.readUInt16LE(cdOff + 10);
    const crc = buf.readUInt32LE(cdOff + 16);
    const compressedSize = buf.readUInt32LE(cdOff + 20);
    const size = buf.readUInt32LE(cdOff + 24);
    const nameLen = buf.readUInt16LE(cdOff + 28);
    const extraLen = buf.readUInt16LE(cdOff + 30);
    const commentLen = buf.readUInt16LE(cdOff + 32);
    const localOff = buf.readUInt32LE(cdOff + 42);
    const name = buf.slice(cdOff + 46, cdOff + 46 + nameLen).toString("utf8");
    entries.push({ name, size, compressedSize, method, offset: localOff, crc });
    cdOff += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function extractZipEntry(buf: Buffer, entry: { offset: number; method: number; compressedSize: number }): Buffer {
  const sig = buf.readUInt32LE(entry.offset); if (sig !== 0x04034b50) throw new Error("bad local header");
  const nameLen = buf.readUInt16LE(entry.offset + 26);
  const extraLen = buf.readUInt16LE(entry.offset + 28);
  const dataStart = entry.offset + 30 + nameLen + extraLen;
  const data = buf.slice(dataStart, dataStart + entry.compressedSize);
  if (entry.method === 0) return data; // stored
  if (entry.method === 8) return inflateRawSync(data); // deflate
  throw new Error(`zip method ${entry.method} not supported`);
}

// -------- image dimensions --------
function imageDimensions(buf: Buffer): { width: number; height: number; format: string } | null {
  if (buf.slice(0, 8).toString("hex") === "89504e470d0a1a0a") {
    return { format: "png", width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  }
  if (buf[0] === 0xff && buf[1] === 0xd8) {
    let i = 2;
    while (i < buf.length) {
      while (buf[i] !== 0xff && i < buf.length) i++;
      while (buf[i] === 0xff && i < buf.length) i++;
      const marker = buf[i]; i++;
      if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
        return { format: "jpeg", height: buf.readUInt16BE(i + 3), width: buf.readUInt16BE(i + 5) };
      }
      i += buf.readUInt16BE(i);
    }
  }
  if (buf.slice(0, 6).toString() === "GIF87a" || buf.slice(0, 6).toString() === "GIF89a") {
    return { format: "gif", width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) };
  }
  if (buf.slice(0, 4).toString() === "RIFF" && buf.slice(8, 12).toString() === "WEBP") {
    // VP8L
    if (buf.slice(12, 16).toString() === "VP8L") {
      const b0 = buf[21], b1 = buf[22], b2 = buf[23], b3 = buf[24];
      return { format: "webp", width: 1 + (((b1 & 0x3f) << 8) | b0), height: 1 + (((b3 & 0xf) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6)) };
    }
    if (buf.slice(12, 16).toString() === "VP8X") {
      return { format: "webp", width: 1 + buf.readUIntLE(24, 3), height: 1 + buf.readUIntLE(27, 3) };
    }
  }
  return null;
}

async function sessionFetch(session: ReturnType<typeof hub.getSession>, url: string): Promise<Buffer> {
  const r = await session.context.request.fetch(url, { ignoreHTTPSErrors: true });
  return r.body();
}

const DEFAULT_DIR = "/tmp/browser-mcp-downloads";

export const fileTools: ToolDef[] = [
  {
    name: "file_download",
    description: "Download a single URL to disk via the session (shares cookies/headers). Returns path + size + sniffed MIME + sha256.",
    schema: z.object({ url: z.string().url(), path: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      try {
        const buf = await sessionFetch(s, a.url);
        const out = a.path ?? join(DEFAULT_DIR, new URL(a.url).hostname, (new URL(a.url).pathname.replace(/^\/|\/$/g, "") || "index") + (extname(new URL(a.url).pathname) ? "" : ".html"));
        await mkdir(dirname(out), { recursive: true });
        await writeFile(out, buf);
        return ok({ url: a.url, path: out, bytes: buf.length, mime: sniffMime(buf), sha256: createHash("sha256").update(buf).digest("hex") });
      } catch (e: any) { return err(e?.message ?? String(e)); }
    },
  },
  {
    name: "file_download_all_assets",
    description: "Download every resource the page loaded — scripts, stylesheets, images, fonts, media. Saves to a per-host directory, preserving the URL path.",
    schema: z.object({
      saveDir: z.string().optional(),
      sameOriginOnly: z.boolean().optional(),
      types: z.array(z.enum(["script", "stylesheet", "image", "font", "media", "document", "xhr", "fetch", "other"])).optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const origin = (() => { try { return new URL(s.page.url()).origin; } catch { return null; } })();
      const base = a.saveDir ?? join(DEFAULT_DIR, origin ? new URL(origin).hostname : "default");
      await mkdir(base, { recursive: true });
      const typeFilter = a.types ? new Set(a.types) : null;
      const assets: any[] = [];
      const seen = new Set<string>();
      for (const req of s.requests) {
        if (seen.has(req.url)) continue; seen.add(req.url);
        if (!req.status || req.status >= 400) continue;
        if (a.sameOriginOnly !== false && origin && !req.url.startsWith(origin)) continue;
        if (typeFilter && !typeFilter.has(req.resourceType as any)) continue;
        try {
          const buf = await sessionFetch(s, req.url);
          const u = new URL(req.url);
          const safePath = u.pathname.replace(/^\//, "") || "index";
          const diskPath = join(base, safePath + (extname(safePath) ? "" : ".html"));
          await mkdir(dirname(diskPath), { recursive: true });
          await writeFile(diskPath, buf);
          assets.push({ url: req.url, path: diskPath, bytes: buf.length, resourceType: req.resourceType });
        } catch (e: any) { /* pumppet */ }
      }
      return ok({ saveDir: base, count: assets.length, assets });
    },
  },
  {
    name: "file_save_page_archive",
    description: "Save the current page (HTML + every linked JS/CSS/image/font) into a folder as a static mirror. Rewrites <script src=>, <link href=>, <img src=> to point at the local copies.",
    schema: z.object({ saveDir: z.string().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const url = s.page.url();
      const base = a.saveDir ?? join(DEFAULT_DIR, "archive-" + Date.now());
      await mkdir(base, { recursive: true });
      let html = await s.page.content();
      const linked = await s.page.$$eval('script[src],link[rel="stylesheet"],img[src]', (els: any[]) => els.map((e) => ({ tag: e.tagName.toLowerCase(), src: e.src || e.href })).filter((x: any) => x.src));
      const saved: any[] = [];
      for (const link of linked) {
        try {
          const buf = await sessionFetch(s, link.src);
          const u = new URL(link.src);
          const name = basename(u.pathname) || "asset";
          const sub = link.tag === "script" ? "js" : link.tag === "link" ? "css" : "img";
          const diskPath = join(base, sub, name);
          await mkdir(dirname(diskPath), { recursive: true });
          await writeFile(diskPath, buf);
          const rel = `${sub}/${name}`;
          html = html.split(link.src).join(rel);
          saved.push({ original: link.src, local: diskPath, bytes: buf.length });
        } catch { /* pumppet */ }
      }
      const indexPath = join(base, "index.html");
      await writeFile(indexPath, html);
      return ok({ url, saveDir: base, index: indexPath, assets: saved.length, saved });
    },
  },
  {
    name: "file_list",
    description: "List files in a local directory with sizes + mtimes. Recursive optional.",
    schema: z.object({ dir: z.string(), recursive: z.boolean().optional(), maxEntries: z.number().int().positive().optional() }),
    handler: async (a) => {
      const limit = a.maxEntries ?? 500;
      const out: any[] = [];
      const walk = async (d: string) => {
        if (out.length >= limit) return;
        const entries = await readdir(d, { withFileTypes: true });
        for (const e of entries) {
          if (out.length >= limit) break;
          const full = join(d, e.name);
          try {
            const st = await stat(full);
            out.push({ path: full, type: e.isDirectory() ? "dir" : "file", bytes: st.size, mtime: st.mtimeMs });
            if (a.recursive && e.isDirectory()) await walk(full);
          } catch { /* pumppet */ }
        }
      };
      await walk(resolve(a.dir));
      return ok({ dir: resolve(a.dir), count: out.length, entries: out });
    },
  },
  {
    name: "file_inspect",
    description: "Inspect a local file — size, MIME (magic bytes), text/binary classification, sha256, md5, image dimensions where applicable.",
    schema: z.object({ path: z.string(), maxBytes: z.number().int().positive().optional() }),
    handler: async (a) => {
      const buf = await readFile(a.path);
      const slice = buf.slice(0, a.maxBytes ?? buf.length);
      const mime = sniffMime(buf);
      const dims = /^image\//.test(mime) ? imageDimensions(buf) : null;
      const printable = (() => { let n = 0; for (let i = 0; i < Math.min(1024, buf.length); i++) if (buf[i] === 9 || buf[i] === 10 || buf[i] === 13 || (buf[i] >= 32 && buf[i] <= 126)) n++; return n / Math.min(1024, buf.length); })();
      return ok({
        path: resolve(a.path), bytes: buf.length, mime,
        isText: printable > 0.9,
        sha256: createHash("sha256").update(buf).digest("hex"),
        md5: createHash("md5").update(buf).digest("hex"),
        image: dims,
        preview: printable > 0.9 ? slice.toString("utf8").slice(0, 2000) : null,
      });
    },
  },
  {
    name: "file_view_code",
    description: "Read a code file with line numbers for easy quoting (fileName:line references). Optional range.",
    schema: z.object({ path: z.string(), fromLine: z.number().int().positive().optional(), toLine: z.number().int().positive().optional() }),
    handler: async (a) => {
      const text = await readFile(a.path, "utf8");
      const lines = text.split(/\r?\n/);
      const start = (a.fromLine ?? 1) - 1;
      const end = Math.min(lines.length, a.toLine ?? lines.length);
      const width = String(end).length;
      const out = lines.slice(start, end).map((l, i) => `${String(start + i + 1).padStart(width, " ")}  ${l}`).join("\n");
      return ok({ path: a.path, totalLines: lines.length, shown: `${start + 1}-${end}`, code: out });
    },
  },
  {
    name: "file_hex_dump",
    description: "Hex-dump a file (16 bytes/row with ASCII sidebar).",
    schema: z.object({ path: z.string(), offset: z.number().int().min(0).optional(), length: z.number().int().positive().optional() }),
    handler: async (a) => {
      const buf = await readFile(a.path);
      const start = a.offset ?? 0; const end = Math.min(buf.length, start + (a.length ?? 512));
      const lines: string[] = [];
      for (let i = start; i < end; i += 16) {
        const row = buf.slice(i, Math.min(end, i + 16));
        const hex = Array.from(row).map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(48);
        const ascii = Array.from(row).map((b) => (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".").join("");
        lines.push(`${i.toString(16).padStart(8, "0")}  ${hex}  ${ascii}`);
      }
      return ok({ path: a.path, bytes: buf.length, dump: lines.join("\n") });
    },
  },
  {
    name: "file_strings",
    description: "Extract printable strings (>= N chars) from a binary.",
    schema: z.object({ path: z.string(), minLength: z.number().int().min(2).optional(), limit: z.number().int().positive().optional() }),
    handler: async (a) => {
      const buf = await readFile(a.path);
      const n = a.minLength ?? 4;
      const re = new RegExp(`[\\x20-\\x7e]{${n},}`, "g");
      const text = buf.toString("latin1");
      const matches = text.match(re) ?? [];
      return ok({ path: a.path, count: matches.length, strings: matches.slice(0, a.limit ?? 500) });
    },
  },
  {
    name: "file_zip_list",
    description: "List the files inside a ZIP archive (central directory read, no extraction).",
    schema: z.object({ path: z.string() }),
    handler: async (a) => {
      try {
        const buf = await readFile(a.path);
        const entries = readZipCentralDir(buf);
        return ok({ path: a.path, count: entries.length, entries: entries.map((e) => ({ name: e.name, size: e.size, compressedSize: e.compressedSize, method: e.method === 0 ? "stored" : e.method === 8 ? "deflate" : `method:${e.method}` })) });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "file_zip_extract",
    description: "Extract one entry (or all) from a ZIP into a target directory. Pure-JS inflate, no system `unzip` needed.",
    schema: z.object({ path: z.string(), toDir: z.string(), entry: z.string().optional().describe("if omitted, extract all"), max: z.number().int().positive().optional() }),
    handler: async (a) => {
      try {
        const buf = await readFile(a.path);
        const entries = readZipCentralDir(buf);
        await mkdir(resolve(a.toDir), { recursive: true });
        const toExtract = a.entry ? entries.filter((e) => e.name === a.entry) : entries.slice(0, a.max ?? 1000);
        const written: string[] = [];
        for (const e of toExtract) {
          if (e.name.endsWith("/")) continue;
          const out = resolve(a.toDir, e.name);
          if (!out.startsWith(resolve(a.toDir))) continue; // zip-slip
          await mkdir(dirname(out), { recursive: true });
          await writeFile(out, extractZipEntry(buf, e));
          written.push(out);
        }
        return ok({ extracted: written.length, files: written });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "file_pdf_text",
    description: "Extract text from a PDF via pattern-based parsing (works for most text-based PDFs; image-only PDFs need OCR).",
    schema: z.object({ path: z.string(), maxChars: z.number().int().positive().optional() }),
    handler: async (a) => {
      try {
        const buf = await readFile(a.path);
        if (buf.slice(0, 4).toString() !== "%PDF") return err("not a PDF");
        // Streams can be deflated — walk through, inflate where /FlateDecode
        const chunks: string[] = [];
        const text = buf.toString("latin1");
        const streamRe = /<<\s*([^>]+?)>>\s*stream\s*(\n|\r\n)?([\s\S]*?)endstream/g;
        let m: RegExpExecArray | null;
        while ((m = streamRe.exec(text))) {
          const dict = m[1]; const data = m[3];
          let bytes = Buffer.from(data, "latin1");
          if (/\/FlateDecode/.test(dict)) {
            try { bytes = inflateRawSync(bytes.slice(0, bytes.length - 1), { finishFlush: 2 }); } catch { try { bytes = inflateRawSync(bytes); } catch { continue; } }
          }
          const decoded = bytes.toString("latin1");
          // extract text operators: Tj and TJ
          const texts = Array.from(decoded.matchAll(/\(((?:\\.|[^\\()])*)\)\s*Tj/g)).map((m) => m[1]);
          const arrs = Array.from(decoded.matchAll(/\[(.*?)\]\s*TJ/g)).flatMap((m) => Array.from(m[1].matchAll(/\(((?:\\.|[^\\()])*)\)/g)).map((m) => m[1]));
          chunks.push([...texts, ...arrs].map((t) => t.replace(/\\\(/g, "(").replace(/\\\)/g, ")").replace(/\\\\/g, "\\").replace(/\\(\d{1,3})/g, (_m, o) => String.fromCharCode(parseInt(o, 8)))).join(" "));
        }
        const combined = chunks.join("\n").replace(/\s+/g, " ").trim();
        return ok({ path: a.path, text: combined.slice(0, a.maxChars ?? 20000), truncated: combined.length > (a.maxChars ?? 20000), length: combined.length });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "file_image_info",
    description: "Image dimensions + format via header parsing (no decode).",
    schema: z.object({ path: z.string() }),
    handler: async (a) => {
      const buf = await readFile(a.path);
      const info = imageDimensions(buf);
      if (!info) return err("not a supported image");
      return ok({ ...info, bytes: buf.length });
    },
  },
  {
    name: "file_exif",
    description: "Extract EXIF tags from a JPEG (basic — camera make/model, datetime, GPS, orientation, dimensions).",
    schema: z.object({ path: z.string() }),
    handler: async (a) => {
      try {
        const buf = await readFile(a.path);
        if (buf[0] !== 0xff || buf[1] !== 0xd8) return err("not a JPEG");
        // Find APP1 (Exif)
        let i = 2;
        while (i < buf.length - 4) {
          if (buf[i] !== 0xff) break;
          const marker = buf[i + 1];
          const len = buf.readUInt16BE(i + 2);
          if (marker === 0xe1 && buf.slice(i + 4, i + 10).toString() === "Exif\0\0") {
            const tiff = buf.slice(i + 10);
            const le = tiff[0] === 0x49;
            const u16 = (o: number) => le ? tiff.readUInt16LE(o) : tiff.readUInt16BE(o);
            const u32 = (o: number) => le ? tiff.readUInt32LE(o) : tiff.readUInt32BE(o);
            const ifd0 = u32(4);
            const count = u16(ifd0);
            const tags: Record<string, any> = {};
            const names: Record<number, string> = { 0x010f: "Make", 0x0110: "Model", 0x0112: "Orientation", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized", 0x0132: "DateTime", 0x8769: "ExifIFDPointer", 0x8825: "GPSInfoIFDPointer", 0xa002: "PixelXDimension", 0xa003: "PixelYDimension", 0x010e: "ImageDescription", 0x013b: "Artist", 0x8298: "Copyright" };
            for (let j = 0; j < count; j++) {
              const off = ifd0 + 2 + j * 12;
              const tag = u16(off);
              const type = u16(off + 2);
              const cnt = u32(off + 4);
              let val: any = u32(off + 8);
              if (type === 2 && cnt > 4) { const ptr = val; val = tiff.slice(ptr, ptr + cnt - 1).toString("latin1"); }
              else if (type === 2) { val = tiff.slice(off + 8, off + 8 + cnt - 1).toString("latin1"); }
              tags[names[tag] ?? `tag_0x${tag.toString(16)}`] = val;
            }
            return ok({ path: a.path, exif: tags });
          }
          i += 2 + len;
        }
        return ok({ path: a.path, exif: null, note: "no EXIF segment" });
      } catch (e: any) { return err(e.message); }
    },
  },
  {
    name: "file_js_analyze",
    description: "Static-ish analysis of a JavaScript file — count functions/classes/imports, extract fetch/XMLHttpRequest/axios URL calls, flag eval/Function/innerHTML sinks, detect minification.",
    schema: z.object({ path: z.string() }),
    handler: async (a) => {
      const text = await readFile(a.path, "utf8");
      const lines = text.split(/\r?\n/);
      const minified = text.length / Math.max(1, lines.length) > 300;
      const fetchCalls = Array.from(text.matchAll(/\bfetch\s*\(\s*["'`]([^"'`]+)["'`]/g)).map((m) => m[1]);
      const axiosCalls = Array.from(text.matchAll(/\baxios\.(?:get|post|put|delete|patch|request)\s*\(\s*["'`]([^"'`]+)["'`]/g)).map((m) => m[1]);
      const xhrOpens = Array.from(text.matchAll(/\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^"'`]+)["'`]/g)).map((m) => ({ method: m[1], url: m[2] }));
      const dangerousSinks = {
        eval: (text.match(/\beval\s*\(/g) ?? []).length,
        Function: (text.match(/\bnew\s+Function\s*\(/g) ?? []).length,
        innerHTML: (text.match(/\.innerHTML\s*=/g) ?? []).length,
        documentWrite: (text.match(/document\.write\s*\(/g) ?? []).length,
        setTimeout_string: (text.match(/setTimeout\s*\(\s*["'`]/g) ?? []).length,
      };
      const counts = {
        functions: (text.match(/\bfunction\s+\w+/g) ?? []).length + (text.match(/=>\s*\{/g) ?? []).length,
        classes: (text.match(/\bclass\s+\w+/g) ?? []).length,
        imports: (text.match(/\bimport\s+[^;]+from/g) ?? []).length,
        requires: (text.match(/\brequire\s*\(/g) ?? []).length,
        exports: (text.match(/\bexport\s+/g) ?? []).length,
      };
      return ok({ path: a.path, bytes: text.length, lines: lines.length, minified, counts, dangerousSinks, apiCalls: { fetch: fetchCalls, axios: axiosCalls, xhr: xhrOpens } });
    },
  },
  {
    name: "file_json_tree",
    description: "Pretty tree view of a JSON file — type of each node, array lengths, object key counts.",
    schema: z.object({ path: z.string(), maxDepth: z.number().int().positive().optional() }),
    handler: async (a) => {
      const text = await readFile(a.path, "utf8");
      let data: any; try { data = JSON.parse(text); } catch (e: any) { return err(e.message); }
      const lines: string[] = [];
      const walk = (v: any, prefix: string, name: string, depth: number) => {
        if (depth > (a.maxDepth ?? 5)) return;
        if (v === null) lines.push(`${prefix}${name}: null`);
        else if (Array.isArray(v)) { lines.push(`${prefix}${name}: Array[${v.length}]`); for (let i = 0; i < Math.min(v.length, 5); i++) walk(v[i], prefix + "  ", `[${i}]`, depth + 1); }
        else if (typeof v === "object") { const keys = Object.keys(v); lines.push(`${prefix}${name}: Object{${keys.length} keys}`); for (const k of keys.slice(0, 20)) walk(v[k], prefix + "  ", k, depth + 1); }
        else lines.push(`${prefix}${name}: ${typeof v} (${JSON.stringify(v).slice(0, 60)})`);
      };
      walk(data, "", "$", 0);
      return ok({ path: a.path, tree: lines.join("\n") });
    },
  },
  {
    name: "file_diff",
    description: "Line-diff two text files — adds, removes, equals.",
    schema: z.object({ a: z.string(), b: z.string() }),
    handler: async (a) => {
      const A = (await readFile(a.a, "utf8")).split(/\r?\n/);
      const B = (await readFile(a.b, "utf8")).split(/\r?\n/);
      // Simple LCS diff
      const dp: number[][] = Array.from({ length: A.length + 1 }, () => Array(B.length + 1).fill(0));
      for (let i = 1; i <= A.length; i++) for (let j = 1; j <= B.length; j++) dp[i][j] = A[i-1] === B[j-1] ? dp[i-1][j-1] + 1 : Math.max(dp[i-1][j], dp[i][j-1]);
      const out: string[] = [];
      let i = A.length, j = B.length;
      while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && A[i-1] === B[j-1]) { out.unshift(`  ${A[i-1]}`); i--; j--; }
        else if (j > 0 && (i === 0 || dp[i][j-1] >= dp[i-1][j])) { out.unshift(`+ ${B[j-1]}`); j--; }
        else { out.unshift(`- ${A[i-1]}`); i--; }
      }
      const adds = out.filter((l) => l.startsWith("+ ")).length;
      const removes = out.filter((l) => l.startsWith("- ")).length;
      return ok({ adds, removes, diff: out.slice(0, 500).join("\n") });
    },
  },
  {
    name: "file_mirror_site",
    description: "Crawl a site (same-origin, breadth-first) and save every reachable page + its assets to disk. Returns a tree.",
    schema: z.object({
      startUrl: z.string().url(),
      saveDir: z.string().optional(),
      maxPages: z.number().int().positive().optional(),
      maxDepth: z.number().int().positive().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const origin = new URL(a.startUrl).origin;
      const base = a.saveDir ?? join(DEFAULT_DIR, "mirror-" + new URL(a.startUrl).hostname + "-" + Date.now());
      await mkdir(base, { recursive: true });
      const seen = new Set<string>([a.startUrl]);
      const queue: Array<{ url: string; depth: number }> = [{ url: a.startUrl, depth: 0 }];
      const written: Array<{ url: string; path: string; bytes: number }> = [];
      while (queue.length && written.length < (a.maxPages ?? 50)) {
        const { url, depth } = queue.shift()!;
        try {
          const r = await s.context.request.fetch(url, { ignoreHTTPSErrors: true, maxRedirects: 3 });
          const buf = await r.body();
          const u = new URL(url);
          const safe = u.pathname.replace(/^\//, "") || "index";
          const diskPath = join(base, u.hostname, safe + (extname(safe) ? "" : ".html"));
          await mkdir(dirname(diskPath), { recursive: true });
          await writeFile(diskPath, buf);
          written.push({ url, path: diskPath, bytes: buf.length });
          if (depth < (a.maxDepth ?? 2) && /text\/html/.test(r.headers()["content-type"] ?? "")) {
            const html = buf.toString("utf8").slice(0, 500000);
            for (const m of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
              try { const abs = new URL(m[1], url).toString(); if (new URL(abs).origin === origin && !seen.has(abs)) { seen.add(abs); queue.push({ url: abs, depth: depth + 1 }); } } catch {}
            }
          }
        } catch { /* pumppet */ }
      }
      return ok({ startUrl: a.startUrl, saveDir: base, pageCount: written.length, pages: written });
    },
  },
];
