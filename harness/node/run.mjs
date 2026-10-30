#!/usr/bin/env node
// Node.js harness: runs every corpus case through each library and writes
// results/raw/node.jsonl following harness/SCHEMA.md. No network I/O.
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");
const CORPUS = path.join(ROOT, "corpus", "corpus.json");
const OUT = process.argv[2] || path.join(ROOT, "results", "raw", "node.jsonl");

const corpus = JSON.parse(fs.readFileSync(CORPUS, "utf8"));
const cases = corpus.cases;
const byId = Object.fromEntries(cases.map((c) => [c.id, c]));

const ver = (name) => JSON.parse(fs.readFileSync(path.join(HERE, "node_modules", name, "package.json"), "utf8")).version;
const domainOf = (addr) => (addr.includes("@") ? addr.slice(addr.lastIndexOf("@") + 1) : addr);
// host of a URL string *without* parsing/normalising it: authority up to the first / ? #, minus userinfo and port
const rawHost = (u) => { const a = String(u).replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "").split(/[/?#]/)[0]; return a.slice(a.lastIndexOf("@") + 1).replace(/:\d*$/, ""); };

// adapter: {library, version, fn, surface, kind, call(value, case) -> {accepted, output, output_kind, error}}
const ADAPTERS = [];
const SKIPPED = [];
const ok = (output, kind) => ({ accepted: true, output, output_kind: kind, error: null });
const rej = (e) => ({ accepted: false, output: null, output_kind: "rejected", error: String(e && (e.message || e)).slice(0, 200) });
function add(library, version, fn, surface, kind, call) {
  ADAPTERS.push({ library, version, fn, surface, kind, call: (v, c) => { try { return call(v, c); } catch (e) { return rej(e); } } });
}

// --- Node built-ins --------------------------------------------------------
const NODE = process.version;
add("node", NODE, "new URL(url).hostname  [WHATWG URL]", "url", "downstream", (v) => {
  const u = new URL(v); if (!u.hostname) throw new Error("empty hostname"); return ok(u.hostname, "parsed");
});
add("node", NODE, "url.parse(url).hostname  [legacy parser]", "url", "downstream", (v) => {
  const h = url.parse(v).hostname; if (!h) throw new Error("no hostname"); return ok(h, "parsed");
});
add("node", NODE, "url.domainToASCII(host)", "host", "downstream", (v) => {
  const r = url.domainToASCII(v); if (r === "") throw new Error("domainToASCII returned ''"); return ok(r, "normalized");
});
add("node", NODE, "new Request(url).url  [fetch/undici; host of serialised URL]", "url", "downstream", (v) => {
  const r = new Request(v); return ok(new URL(r.url).hostname, "normalized");
});

// --- whatwg-url / tr46 -----------------------------------------------------
try {
  const wu = require("whatwg-url");
  add("whatwg-url", ver("whatwg-url"), "new whatwgUrl.URL(url).hostname", "url", "downstream", (v) => {
    const u = new wu.URL(v); if (!u.hostname) throw new Error("empty hostname"); return ok(u.hostname, "parsed");
  });
} catch (e) { SKIPPED.push(`whatwg-url: ${e.message}`); }
try {
  const tr46 = require("tr46");
  const strict = { checkHyphens: true, checkBidi: true, checkJoiners: true, useSTD3ASCIIRules: true, transitionalProcessing: false, verifyDNSLength: true };
  const lenient = { checkHyphens: false, checkBidi: true, checkJoiners: true, useSTD3ASCIIRules: false, transitionalProcessing: false, verifyDNSLength: false };
  add("tr46", ver("tr46"), "tr46.toASCII(host, strict UTS 46 options)", "host", "downstream", (v) => {
    const r = tr46.toASCII(v, strict); if (r === null) throw new Error("toASCII returned null"); return ok(r, "normalized");
  });
  add("tr46", ver("tr46"), "tr46.toASCII(host, WHATWG options)", "host", "downstream", (v) => {
    const r = tr46.toASCII(v, lenient); if (r === null) throw new Error("toASCII returned null"); return ok(r, "normalized");
  });
} catch (e) { SKIPPED.push(`tr46: ${e.message}`); }

// --- punycode (npm, RFC 3492 only; the deprecated core module has the same code)
try {
  const punycode = require("punycode/");
  add("punycode", ver("punycode"), "punycode.toASCII(host)  [RFC 3492 only, no UTS 46]", "host", "downstream", (v) => ok(punycode.toASCII(v), "normalized"));
} catch (e) { SKIPPED.push(`punycode: ${e.message}`); }

// --- public suffix splitters ----------------------------------------------
try {
  const psl = require("psl");
  add("psl", ver("psl"), "psl.parse(host).domain  [registrable domain]", "host", "downstream", (v) => {
    const r = psl.parse(v); if (r.error || !r.domain) throw new Error(r.error ? `${r.error.code}: ${r.error.message}` : "no registrable domain"); return ok(r.domain, "parsed");
  });
  add("psl", ver("psl"), "psl.isValid(host)", "host", "validator", (v, c) => psl.isValid(v) ? ok(c.host, "passthrough") : rej("isValid false"));
} catch (e) { SKIPPED.push(`psl: ${e.message}`); }
try {
  const tldts = require("tldts");
  add("tldts", ver("tldts"), "tldts.parse(host).domain  [registrable domain]", "host", "downstream", (v) => {
    const r = tldts.parse(v); if (!r.domain) throw new Error(`no registrable domain (hostname=${JSON.stringify(r.hostname)})`); return ok(r.domain, "parsed");
  });
  add("tldts", ver("tldts"), "tldts.getHostname(host)", "host", "downstream", (v) => {
    const r = tldts.getHostname(v); if (!r) throw new Error("null hostname"); return ok(r, "parsed");
  });
} catch (e) { SKIPPED.push(`tldts: ${e.message}`); }

// --- validator.js ----------------------------------------------------------
try {
  const validator = require("validator");
  const V = ver("validator");
  add("validator", V, "validator.isURL(url)", "url", "validator", (v, c) => validator.isURL(v) ? ok(c.host, "passthrough") : rej("isURL false"));
  add("validator", V, "validator.isURL(url, {require_tld:true, allow_underscores:false})", "url", "validator", (v, c) => validator.isURL(v, { require_tld: true, allow_underscores: false }) ? ok(c.host, "passthrough") : rej("isURL false"));
  add("validator", V, "validator.isFQDN(host)", "host", "validator", (v, c) => validator.isFQDN(v) ? ok(c.host, "passthrough") : rej("isFQDN false"));
  add("validator", V, "validator.isEmail(addr)", "email", "validator", (v) => validator.isEmail(v) ? ok(domainOf(v), "passthrough") : rej("isEmail false"));
} catch (e) { SKIPPED.push(`validator: ${e.message}`); }

// --- zod -------------------------------------------------------------------
try {
  const z = require("zod");
  const Z = ver("zod");
  const zurl = z.url(), zemail = z.email(), zhost = z.hostname(), zlegacy = z.string().url(), zlegacyEmail = z.string().email();
  const zrun = (schema, v, out) => { const r = schema.safeParse(v); return r.success ? ok(out(r.data), "passthrough") : rej(r.error.issues.map((i) => i.message).join("; ")); };
  add("zod", Z, "z.url().safeParse(url)", "url", "validator", (v) => zrun(zurl, v, rawHost));
  add("zod", Z, "z.string().url().safeParse(url)", "url", "validator", (v) => zrun(zlegacy, v, rawHost));
  add("zod", Z, "z.email().safeParse(addr)", "email", "validator", (v) => zrun(zemail, v, domainOf));
  add("zod", Z, "z.string().email().safeParse(addr)", "email", "validator", (v) => zrun(zlegacyEmail, v, domainOf));
  add("zod", Z, "z.hostname().safeParse(host)", "host", "validator", (v, c) => zrun(zhost, v, () => c.host));
} catch (e) { SKIPPED.push(`zod: ${e.message}`); }

// --- yup -------------------------------------------------------------------
try {
  const yup = require("yup");
  const Y = ver("yup");
  add("yup", Y, "yup.string().url().validateSync(url)", "url", "validator", (v) => ok(rawHost(yup.string().url().validateSync(v)), "passthrough"));
  add("yup", Y, "yup.string().email().validateSync(addr)", "email", "validator", (v) => { yup.string().email().validateSync(v); return ok(domainOf(v), "passthrough"); });
} catch (e) { SKIPPED.push(`yup: ${e.message}`); }

// --- joi -------------------------------------------------------------------
try {
  const Joi = require("joi");
  const J = ver("joi");
  const jrun = (schema, v, out) => { const r = schema.validate(v); return r.error ? rej(r.error.message) : ok(out(r.value), "passthrough"); };
  add("joi", J, "Joi.string().uri().validate(url)", "url", "validator", (v) => jrun(Joi.string().uri(), v, rawHost));
  add("joi", J, "Joi.string().domain().validate(host)", "host", "validator", (v, c) => jrun(Joi.string().domain(), v, () => c.host));
  add("joi", J, "Joi.string().hostname().validate(host)", "host", "validator", (v, c) => jrun(Joi.string().hostname(), v, () => c.host));
  add("joi", J, "Joi.string().email({tlds:false}).validate(addr)", "email", "validator", (v) => jrun(Joi.string().email({ tlds: false }), v, domainOf));
} catch (e) { SKIPPED.push(`joi: ${e.message}`); }

// --- email-validator -------------------------------------------------------
try {
  const ev = require("email-validator");
  add("email-validator", ver("email-validator"), "emailValidator.validate(addr)", "email", "validator", (v) => ev.validate(v) ? ok(domainOf(v), "passthrough") : rej("validate false"));
} catch (e) { SKIPPED.push(`email-validator: ${e.message}`); }

// --- ajv + ajv-formats -----------------------------------------------------
try {
  const Ajv = require("ajv");
  const addFormats = require("ajv-formats");
  const ajv = new Ajv({ strict: false });
  addFormats(ajv);
  const A = `${ver("ajv")}+formats-${ver("ajv-formats")}`;
  const mk = (fmt) => ajv.compile({ type: "string", format: fmt });
  const fmts = { uri: ["url", mk("uri")], hostname: ["host", mk("hostname")], email: ["email", mk("email")] };
  for (const [fmt, [surface, validate]] of Object.entries(fmts)) {
    add("ajv-formats", A, `ajv format "${fmt}"`, surface, "validator", (v, c) => validate(v) ? ok(surface === "email" ? domainOf(v) : c.host, "passthrough") : rej(ajv.errorsText(validate.errors)));
  }
  // idn-hostname / idn-email exist only in the full ("fast" is default) mode
  const Ajv2 = new Ajv({ strict: false }); addFormats(Ajv2, { mode: "full" });
  for (const [fmt, surface] of [["idn-hostname", "host"], ["idn-email", "email"]]) {
    if (!Ajv2.formats[fmt]) { SKIPPED.push(`ajv-formats: no format ${fmt}`); continue; }
    const validate = Ajv2.compile({ type: "string", format: fmt });
    add("ajv-formats", A, `ajv format "${fmt}" (mode full)`, surface, "validator", (v, c) => validate(v) ? ok(surface === "email" ? domainOf(v) : c.host, "passthrough") : rej(Ajv2.errorsText(validate.errors)));
  }
} catch (e) { SKIPPED.push(`ajv: ${e.message}`); }

// --- self-check ------------------------------------------------------------
const good = byId["ctl-good"], bad = byId["ctl-bad-space"];
const failures = [];
for (const a of ADAPTERS) {
  const r = a.call(good[a.surface], good);
  if (!r.accepted) failures.push(`${a.library} ${a.fn}: rejected known-good ${JSON.stringify(good[a.surface])}: ${r.error}`);
  if (a.kind === "validator" && (a.surface === "host" || a.surface === "email")) {
    const b = a.call(bad[a.surface], bad);
    if (b.accepted) failures.push(`${a.library} ${a.fn}: accepted known-bad ${JSON.stringify(bad[a.surface])}`);
  }
}
if (failures.length) { console.error("SELF-CHECK FAILED:"); for (const f of failures) console.error("  " + f); process.exit(2); }
for (const s of SKIPPED) console.error("SKIP " + s);

// --- run -------------------------------------------------------------------
const esc = (s) => s.replace(/[\u007f-￿]/g, (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
fs.mkdirSync(path.dirname(OUT), { recursive: true });
const lines = [];
const tally = new Map();
for (const a of ADAPTERS) {
  for (const c of cases) {
    if (!c.surfaces.includes(a.surface)) continue;
    const value = c[a.surface];
    const r = a.call(value, c);
    lines.push(esc(JSON.stringify({ ecosystem: "node", runtime: NODE, library: a.library, version: a.version, function: a.fn, surface: a.surface, case_id: c.id, input: value, accepted: r.accepted, output: r.output, output_kind: r.output_kind, error: r.error, kind: a.kind })));
    const k = `${a.library.padEnd(16)} ${a.version.padEnd(22)} ${a.fn}`;
    const t = tally.get(k) || [0, 0]; t[0]++; if (r.accepted) t[1]++; tally.set(k, t);
  }
}
fs.writeFileSync(OUT, lines.join("\n") + "\n");
for (const [k, [n, acc]] of tally) console.error(`${String(acc).padStart(4)}/${String(n).padEnd(4)} ${k}`);
console.error(`wrote ${lines.length} rows from ${ADAPTERS.length} adapters to ${OUT}`);
