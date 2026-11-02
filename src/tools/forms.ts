import { z } from "zod";
import { hub } from "../browser.js";
import { ToolDef, ok, err } from "../types.js";

const sessionArg = { sessionId: z.string().optional() };

// Simple fake data generator — no external dep
const FIRST = ["Alex","Sam","Chris","Jordan","Taylor","Morgan","Casey","Riley","Avery","Quinn","Harper","Rowan","Sage","River","Skyler","Dakota","Phoenix","Blake","Ellis","Finn"];
const LAST = ["Smith","Johnson","Lee","Garcia","Nguyen","Patel","Kim","Chen","Lopez","Taylor","Brown","Wilson","Clark","Walker","Hall","Allen","Young","King","Wright","Scott"];
const CITIES = ["Portland","Austin","Denver","Boston","Seattle","Chicago","Toronto","Vancouver","Dublin","Amsterdam","Berlin","Lisbon","Melbourne","Auckland"];
const STATES = ["CA","NY","TX","FL","WA","OR","CO","MA","IL","GA","AZ","OH","PA","NC"];
const DOMAINS = ["example.com","test.dev","mcpdemo.io","sandbox.test","noreply.local"];

function rand<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }
function randDigits(n: number): string { return Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join(""); }

function fakeFor(name: string, type: string, placeholder: string, label: string): string | boolean {
  const hint = `${name} ${type} ${placeholder} ${label}`.toLowerCase();
  if (type === "checkbox") return hint.includes("terms") || hint.includes("agree") || hint.includes("newsletter") ? true : true;
  if (type === "radio") return true;
  if (type === "email" || /email|e-mail/.test(hint)) return `${rand(FIRST)}.${rand(LAST)}${randDigits(2)}@${rand(DOMAINS)}`.toLowerCase();
  if (type === "tel" || /\bphone\b|\bmobile\b|\btel\b/.test(hint)) return `+1${randDigits(10)}`;
  if (type === "password" || /password|passwd|pwd/.test(hint)) return `MCPtest!${randDigits(4)}`;
  if (type === "url" || /website|url|homepage/.test(hint)) return `https://${rand(FIRST).toLowerCase()}.${rand(DOMAINS)}`;
  if (type === "number" || /age|year|quantity|number|zip|postal/.test(hint)) { if (/zip|postal/.test(hint)) return randDigits(5); if (/age/.test(hint)) return String(20 + Math.floor(Math.random() * 50)); return String(Math.floor(Math.random() * 100)); }
  if (type === "date" || /dob|birth|date/.test(hint)) { const y = 1960 + Math.floor(Math.random() * 50); const m = String(1 + Math.floor(Math.random() * 12)).padStart(2, "0"); const d = String(1 + Math.floor(Math.random() * 28)).padStart(2, "0"); return `${y}-${m}-${d}`; }
  if (/first.*name|given.*name|fname/.test(hint)) return rand(FIRST);
  if (/last.*name|surname|family.*name|lname/.test(hint)) return rand(LAST);
  if (/full.*name|^name$|user.*name|username/.test(hint)) return /user|login/.test(hint) ? `${rand(FIRST)}${randDigits(3)}`.toLowerCase() : `${rand(FIRST)} ${rand(LAST)}`;
  if (/city/.test(hint)) return rand(CITIES);
  if (/state|province|region/.test(hint)) return rand(STATES);
  if (/country/.test(hint)) return "US";
  if (/zip|postal/.test(hint)) return randDigits(5);
  if (/address|street/.test(hint)) return `${randDigits(3)} Main St`;
  if (/company|organization|employer/.test(hint)) return `${rand(LAST)} ${rand(["Labs","Industries","Group","Inc","Co","Systems"])}`;
  if (/subject|topic/.test(hint)) return "Testing form";
  if (/message|comment|note|bio|about|description/.test(hint)) return "This is a sample message submitted via browser-mcp.";
  if (type === "textarea") return "Sample long text content.";
  if (type === "search") return "test query";
  if (type === "color") return "#4b7bec";
  if (type === "range") return "50";
  // last-resort
  return `test${randDigits(3)}`;
}

export const formTools: ToolDef[] = [
  {
    name: "form_detect",
    description: "Inventory every form on the page — their action, method, every field with name/type/placeholder/label/required/options. Rich enough to drive auto-fill or hand-crafted fuzzing.",
    schema: z.object({ ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const data = await s.page.evaluate(() => {
        const labelFor = (el: HTMLElement): string => {
          const id = el.id;
          if (id) { const l = document.querySelector(`label[for="${id}"]`); if (l) return (l as any).innerText?.trim() ?? ""; }
          const parentLabel = el.closest("label");
          return parentLabel ? (parentLabel as any).innerText?.trim() ?? "" : "";
        };
        return Array.from(document.querySelectorAll("form")).map((f: any) => ({
          action: f.action, method: (f.method || "GET").toUpperCase(),
          id: f.id || null, name: f.name || null, autocomplete: f.autocomplete || null,
          enctype: f.enctype || null,
          fields: Array.from(f.querySelectorAll("input,textarea,select,button[type=submit]")).map((i: any) => ({
            tag: i.tagName.toLowerCase(),
            name: i.name || null,
            id: i.id || null,
            type: i.type || i.tagName.toLowerCase(),
            placeholder: i.placeholder || null,
            label: labelFor(i),
            value: i.type === "password" ? "[hidden]" : (i.value ?? "")?.slice?.(0, 100) ?? "",
            required: !!i.required,
            autocomplete: i.autocomplete || null,
            maxlength: i.maxLength > 0 ? i.maxLength : null,
            pattern: i.pattern || null,
            options: i.tagName === "SELECT" ? Array.from(i.options).map((o: any) => ({ value: o.value, text: o.text })) : undefined,
          })),
        }));
      });
      return ok({ count: data.length, forms: data });
    },
  },
  {
    name: "form_autofill_fake",
    description: "Fill every form (or just one by selector) with contextually plausible fake data — detects email/phone/name/password/date/address/username fields by name+placeholder+label and generates realistic values. Does NOT submit.",
    schema: z.object({
      formSelector: z.string().optional().describe("default: first form"),
      skip: z.array(z.string()).optional().describe("field names to leave alone"),
      overrides: z.record(z.union([z.string(), z.boolean()])).optional().describe("force these name/value pairs"),
      submitSelector: z.string().optional().describe("if given, click it after filling"),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const sel = a.formSelector ?? "form";
      const descriptor = await s.page.$$eval(sel, (forms: any[], sel: string) => {
        const f = forms[0]; if (!f) return null;
        const labelFor = (el: HTMLElement): string => { const id = el.id; if (id) { const l = document.querySelector(`label[for="${id}"]`); if (l) return (l as any).innerText?.trim() ?? ""; } return el.closest("label") ? ((el.closest("label") as any).innerText?.trim() ?? "") : ""; };
        const base = sel.includes("form") ? sel : "form";
        return Array.from(f.querySelectorAll("input,textarea,select")).map((i: any) => ({ name: i.name, id: i.id, type: i.type || i.tagName.toLowerCase(), placeholder: i.placeholder || "", label: labelFor(i), selector: i.name ? `${base} [name="${i.name}"]` : (i.id ? `#${i.id}` : "") })).filter((x: any) => x.selector);
      }, sel);
      if (!descriptor || !Array.isArray(descriptor)) return err("no form found");
      const skip = new Set(a.skip ?? []);
      const overrides = a.overrides ?? {};
      const filled: any[] = [];
      for (const f of descriptor) {
        if (skip.has(f.name)) continue;
        const val = overrides[f.name] ?? fakeFor(f.name ?? "", f.type ?? "", f.placeholder ?? "", f.label ?? "");
        try {
          if (f.type === "checkbox" || f.type === "radio") {
            if (val === true) await s.page.check(f.selector);
            else if (val === false) await s.page.uncheck(f.selector);
          } else if (f.type === "select-one" || f.type === "select") {
            const options = await s.page.$$eval(`${f.selector} option`, (os: any[]) => os.map((o) => o.value));
            if (typeof val === "string" && options.includes(val)) await s.page.selectOption(f.selector, val);
            else if (options.length > 1) await s.page.selectOption(f.selector, options[1]);
          } else if (f.type === "file") { /* skip */ }
          else { await s.page.fill(f.selector, String(val)); }
          filled.push({ name: f.name, selector: f.selector, value: f.type === "password" ? "[hidden]" : val });
        } catch (e: any) { filled.push({ name: f.name, error: e?.message }); }
      }
      if (a.submitSelector) await s.page.click(a.submitSelector);
      return ok({ filled });
    },
  },
  {
    name: "form_fill_profile",
    description: "Fill a form from a profile object (firstName, lastName, email, phone, address, …). Matches fields by name/placeholder/label heuristics.",
    schema: z.object({
      profile: z.object({
        firstName: z.string().optional(), lastName: z.string().optional(), fullName: z.string().optional(),
        email: z.string().optional(), phone: z.string().optional(), username: z.string().optional(),
        password: z.string().optional(),
        address: z.string().optional(), city: z.string().optional(), state: z.string().optional(), zip: z.string().optional(), country: z.string().optional(),
        dob: z.string().optional(), company: z.string().optional(), website: z.string().optional(),
        message: z.string().optional(),
      }),
      formSelector: z.string().optional(),
      submitSelector: z.string().optional(),
      ...sessionArg,
    }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const sel = a.formSelector ?? "form";
      const picks: Array<[RegExp, string | undefined]> = [
        [/first.*name|given.*name|fname/i, a.profile.firstName], [/last.*name|surname|family.*name|lname/i, a.profile.lastName],
        [/full.*name|^name$/i, a.profile.fullName ?? (a.profile.firstName && a.profile.lastName ? `${a.profile.firstName} ${a.profile.lastName}` : undefined)],
        [/email/i, a.profile.email], [/phone|mobile|tel/i, a.profile.phone],
        [/user.*name|username|login/i, a.profile.username],
        [/password|passwd|pwd/i, a.profile.password],
        [/address|street/i, a.profile.address], [/city/i, a.profile.city], [/state|province|region/i, a.profile.state],
        [/zip|postal/i, a.profile.zip], [/country/i, a.profile.country],
        [/dob|birth/i, a.profile.dob], [/company|organization|employer/i, a.profile.company], [/website|url|homepage/i, a.profile.website],
        [/message|comment|note|bio|about|description/i, a.profile.message],
      ];
      const filled: any[] = [];
      const fields = await s.page.$$eval(`${sel} input,${sel} textarea,${sel} select`, (els: any[]) => els.map((i) => ({ name: i.name, id: i.id, placeholder: i.placeholder || "", type: i.type || i.tagName.toLowerCase() })));
      for (const f of fields) {
        const hint = `${f.name} ${f.placeholder} ${f.id}`.toLowerCase();
        for (const [re, val] of picks) {
          if (val && re.test(hint)) {
            const sel2 = f.name ? `${sel} [name="${f.name}"]` : (f.id ? `#${f.id}` : "");
            if (!sel2) continue;
            try { await s.page.fill(sel2, val); filled.push({ selector: sel2, value: f.type === "password" ? "[hidden]" : val }); break; } catch {}
          }
        }
      }
      if (a.submitSelector) await s.page.click(a.submitSelector);
      return ok({ filled });
    },
  },
  {
    name: "form_submit_and_capture",
    description: "Click the submit button of a form, then wait for the next response and capture its status/url/body. Useful for seeing exactly what the server returned.",
    schema: z.object({ submitSelector: z.string(), responseUrlPattern: z.string().optional(), timeoutMs: z.number().int().positive().optional(), ...sessionArg }),
    handler: async (a) => {
      const s = hub.getSession(a.sessionId);
      const t = a.timeoutMs ?? 15000;
      try {
        const [resp] = await Promise.all([
          s.page.waitForResponse((r) => a.responseUrlPattern ? new RegExp(a.responseUrlPattern).test(r.url()) : (r.request().method() === "POST" || r.request().method() === "PUT"), { timeout: t }),
          s.page.click(a.submitSelector),
        ]);
        const body = await resp.text().catch(() => "");
        return ok({ status: resp.status(), url: resp.url(), method: resp.request().method(), body: body.slice(0, 20000) });
      } catch (e: any) { return err(e?.message ?? String(e)); }
    },
  },
];
