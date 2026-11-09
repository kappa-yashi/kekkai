#!/usr/bin/env node
// kekkai (結界) — static site boundary & disclosure check (Astro / Cloudflare Pages / Netlify style).
// Zero dependencies. Node 18+.
//
//   kekkai https://www.example.com          scan the live site (read-only GETs)
//   kekkai ./dist                           scan a build output folder (+ its _headers)
//   kekkai ./repo                           scan a git working copy (secrets, ignored files, docs that describe the security setup)
//   kekkai init [dir] [--admin <cms>]       scaffold scripts/kekkai-postbuild.mjs, .gitignore block, kekkai-rules.md (--force overwrites)
//
// Options:
//   --json              machine-readable output
//   --strict            warnings count as failures (exit 1)
//   --no-probe          live mode: skip the "files that should 404" probes
//   --admin <folder>    dist mode: the CMS/admin folder name; it must not be named outside itself
//   --forbid a,b,c      strings that must not appear anywhere in the output (codenames, staging hosts…)
//   --pages N           live mode: how many internal pages to sample from the sitemap (default 5)
//   --no-history        repo mode: skip the git-history secret scan
//   --accept-edge-inline  live: an inline script injected by the CDN (Cloudflare JS detections) is reported as info, not failure
//   --out <file>        also write the report to a file (.json → JSON, .md → markdown, else plain text)
//   --summary           print only warnings and failures, one line each, plus the counts
//   --repo | --dist     force the mode for a folder (default: .git without index.html/_headers → repo, otherwise dist)
//
// Only scan sites you own or are allowed to test.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, extname, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

// ───────────────────────────── cli ─────────────────────────────
const argv = process.argv.slice(2);
const opt = { json: false, strict: false, probe: true, admin: '', forbid: [], pages: 5, history: true, mode: '', acceptEdge: false, out: '', summary: false, force: false, init: false };
const KNOWN_FLAGS = ['--force', '--json', '--strict', '--no-probe', '--no-history', '--accept-edge-inline', '--repo', '--dist', '--admin', '--forbid', '--pages', '--out', '--summary', '-h', '--help'];
const similar = (a) => KNOWN_FLAGS.map((f) => [f, [...f].filter((ch, i) => a[i] === ch).length / Math.max(f.length, a.length)]).sort((x, y) => y[1] - x[1])[0];
let target = '';
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith('-') && !KNOWN_FLAGS.includes(a)) { const [guess, score] = similar(a); console.error(`unknown option ${a}${score > 0.6 ? ` — did you mean ${guess}?` : ''}`); process.exit(2); }
  if (a === 'init' && !target) { opt.init = true; continue; }
  if (a === '--force') opt.force = true;
  else if (a === '--json') opt.json = true;
  else if (a === '--out') opt.out = argv[++i] || '';
  else if (a === '--summary') opt.summary = true;
  else if (a === '--strict') opt.strict = true;
  else if (a === '--no-probe') opt.probe = false;
  else if (a === '--no-history') opt.history = false;
  else if (a === '--accept-edge-inline') opt.acceptEdge = true;
  else if (a === '--repo') opt.mode = 'repo';
  else if (a === '--dist') opt.mode = 'dist';
  else if (a === '--admin') opt.admin = argv[++i] || '';
  else if (a === '--forbid') opt.forbid = (argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
  else if (a === '--pages') opt.pages = Number(argv[++i]) || 5;
  else if (a === '-h' || a === '--help') { usage(); process.exit(0); }
  else target = a;
}
if (!target && !opt.init) { usage(); process.exit(2); }

function usage() {
  console.log(`kekkai (結界) — static site boundary & disclosure check

  kekkai https://www.example.com      live scan (read-only GET requests)
  kekkai ./dist                       scan a build folder (+ _headers)
  kekkai ./repo                       scan a git working copy (auto-detected by .git)
  kekkai init [dir] [--admin <cms>]   scaffold a project: post-build _headers/version.txt script, .gitignore block, build rules

  --json  --summary  --out <file.md|.json|.txt>  --strict  --no-probe  --no-history
  --repo | --dist  --accept-edge-inline  --admin <folder>  --forbid a,b,c  --pages N`);
}

// ───────────────────────────── report ─────────────────────────────
const results = []; // { section, level: pass|warn|fail|info, id, msg, detail? }
const cur = { section: '' };
const section = (s) => { cur.section = s; };
const pass = (id, msg, detail) => results.push({ section: cur.section, level: 'pass', id, msg, detail });
const warn = (id, msg, detail) => results.push({ section: cur.section, level: 'warn', id, msg, detail });
const fail = (id, msg, detail) => results.push({ section: cur.section, level: 'fail', id, msg, detail });
const info = (id, msg, detail) => results.push({ section: cur.section, level: 'info', id, msg, detail });

// ───────────────────────────── helpers ─────────────────────────────
const sha = (algo, s) => `'${algo}-${createHash(algo).update(s, 'utf8').digest('base64')}'`;
const lower = (h) => Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));

function parseCsp(policy) {
  const d = {};
  for (const part of policy.split(';')) {
    const toks = part.trim().split(/\s+/).filter(Boolean);
    if (!toks.length) continue;
    const name = toks[0].toLowerCase();
    // keywords are case-insensitive; hashes and nonces are base64 and must keep their case
    if (!(name in d)) d[name] = toks.slice(1).map((t) => (t.startsWith("'") && !/^'(sha(256|384|512)|nonce)-/i.test(t)) ? t.toLowerCase() : t.replace(/^'(sha(256|384|512)|nonce)-/i, (m) => m.toLowerCase()));
  }
  return d;
}

// Executable inline scripts, inline style attributes and misc facts about one HTML document.
function inspectHtml(html) {
  const out = { inlineScripts: [], externalScripts: [], external: [], eventHandlers: 0, svgInline: 0, svgScripts: 0, svgStyles: 0, svgRefs: [], styleAttrs: 0, styleTags: 0, styleTagBodies: [], jsonld: [], jsonldErrors: [], metaCsp: null, metaCsps: [], generator: null, canonical: null, title: '' };
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = m[1], body = m[2];
    const type = (attrs.match(/\btype\s*=\s*["']?([^"'\s>]*)/i)?.[1] || '').toLowerCase();
    const src = attrs.match(/\bsrc\s*=\s*["']?([^"'\s>]*)/i)?.[1];
    if (type === 'application/ld+json') { out.jsonld.push(body); try { JSON.parse(body); } catch (e) { out.jsonldErrors.push(String(e.message)); } continue; }
    if (type && !['text/javascript', 'application/javascript', 'module', 'text/module'].includes(type)) continue;
    if (src) { out.externalScripts.push(src); out.external.push({ kind: 'script', url: src, integrity: /\bintegrity\s*=/i.test(attrs), crossorigin: /\bcrossorigin\b/i.test(attrs) }); }
    else out.inlineScripts.push({ body, nonce: attrs.match(/\bnonce\s*=\s*["']?([^"'\s>]*)/i)?.[1] || null });
  }
  for (const m of html.matchAll(/<style\b([^>]*)>([\s\S]*?)<\/style>/gi)) out.styleTagBodies.push({ body: m[2], nonce: m[1].match(/\bnonce\s*=\s*["']?([^"'\s>]*)/i)?.[1] || null });
  for (const m of html.matchAll(/<link\b([^>]*)>/gi)) {
    const attrs = m[1];
    if (!/\brel\s*=\s*["']?(stylesheet|modulepreload)\b/i.test(attrs)) continue;
    const href = attrs.match(/\bhref\s*=\s*["']?([^"'\s>]*)/i)?.[1]; if (!href) continue;
    out.external.push({ kind: /stylesheet/i.test(attrs) ? 'stylesheet' : 'modulepreload', url: href, integrity: /\bintegrity\s*=/i.test(attrs), crossorigin: /\bcrossorigin\b/i.test(attrs) });
  }
  // inline event handlers (onclick=, onload= …) are inline script for CSP purposes
  out.eventHandlers = (html.match(/<[a-z][^>]*\son[a-z]+\s*=\s*["']/gi) || []).length;
  // inline <svg>: <script>/<style> inside it, and external references
  for (const m of html.matchAll(/<svg\b[\s\S]*?<\/svg>/gi)) {
    out.svgInline++;
    const svg = m[0];
    out.svgScripts += (svg.match(/<script\b/gi) || []).length;
    out.svgStyles += (svg.match(/<style\b/gi) || []).length;
    for (const r of svg.matchAll(/(?:xlink:)?href\s*=\s*["'](https?:\/\/[^"']+)["']/gi)) out.svgRefs.push(r[1]);
  }
  for (const m of html.matchAll(/<(?:img|object|embed|use|image)\b[^>]*\b(?:src|data|href|xlink:href)\s*=\s*["']([^"']+\.svg(?:[?#][^"']*)?)["']/gi)) out.svgRefs.push(m[1]);
  out.styleAttrs = (html.match(/<[a-z][^>]*\sstyle\s*=\s*["']/gi) || []).length;
  out.styleTags = (html.match(/<style\b/gi) || []).length;
  for (const m of html.matchAll(/<meta[^>]+http-equiv\s*=\s*["']content-security-policy["'][^>]*>/gi)) {
    const cm = m[0].match(/\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i); // the value itself contains 'self' quotes: match the delimiter, not any quote
    const c = cm ? (cm[1] ?? cm[2]) : undefined;
    if (c !== undefined) out.metaCsps.push(c.replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&amp;/g, '&'));
  }
  out.metaCsp = out.metaCsps.length ? out.metaCsps[0] : null;
  out.generator = html.match(/<meta[^>]+name\s*=\s*["']generator["'][^>]*>/i)?.[0] || null;
  out.canonical = html.match(/<link[^>]+rel\s*=\s*["']canonical["'][^>]*href\s*=\s*["']([^"']*)["']/i)?.[1]
    || html.match(/<link[^>]+href\s*=\s*["']([^"']*)["'][^>]*rel\s*=\s*["']canonical["']/i)?.[1] || null;
  out.title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() || '';
  return out;
}

// Email detection with the usual false positives removed (uuid@site.zip, user@host prompts, "pkg@1.2.3").
const EMAIL_RE = /(^|[^/\w.-])([A-Z0-9._%+-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)*\.([A-Z]{2,}))(?![\w.-]*\.(?:zip|tar|gz|7z|js|mjs|css|png|jpg|webp|svg|json|md|html|txt|xml|woff2?))/gi;
const TLDS = new Set('com net org io gr de uk co me eu info page dev app xyz gov edu fr it es nl be ch at se no fi dk pl cz pt ru ua ca us au nz jp cn in br mx ar tv cc ai cloud site online store tech email mail pro biz name studio design art blog ly sh to is im gg lol ie ro hu bg hr rs si sk lt lv ee tr il za kr tw hk sg my id th vn ph cy mt lu li'.split(' '));
// --forbid terms match as whole tokens: "kframe" must not hit "checkFramebufferStatus", but "brand.com" and "brand-v2" still count.
function hasForbidden(s, w) { return new RegExp(`(^|[^a-z0-9])${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![a-z0-9])`, 'i').test(s); }
function findEmails(s, { skipLicense = false } = {}) {
  const out = new Set();
  for (const m of s.matchAll(EMAIL_RE)) {
    if (!TLDS.has(m[3].toLowerCase())) continue;
    if (skipLicense) { const ctx = s.slice(Math.max(0, m.index - 400), m.index); if (/@license|@author|copyright|\(c\)|©|\/\*!|SPDX-License|MIT License|Licensed under/i.test(ctx)) continue; }
    out.add(m[2]);
  }
  return [...out];
}
const TEXT_EXT = new Set(['.html', '.htm', '.xml', '.txt', '.json', '.js', '.mjs', '.css', '.svg', '.webmanifest', '.md', '.rss', '.atom']);

// ── disclosure scanners (shared by live, dist and repo modes) ──
// Well-known credential shapes. Prefixes only; nothing here is a real value.
const SECRET_PATTERNS = [
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/],
  ['private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY/],
  ['GitHub token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ['Stripe key', /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/],
  ['Shopify token', /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['SendGrid key', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/],
  ['Mailgun key', /\bkey-[a-f0-9]{32}\b/],
  ['Twilio key', /\bSK[a-f0-9]{32}\b/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['OpenAI-style key', /\bsk-[A-Za-z0-9_-]{32,}\b/],
  ['Cloudflare API token shape', /\b(?:cf|cloudflare)[_-]?(?:api[_-]?)?token\s*[:=]\s*["']?[A-Za-z0-9_-]{40}\b/i],
  ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ['assignment of a secret', /\b(?:api[_-]?key|secret|password|passwd|client_secret|access[_-]?token|auth[_-]?token|private[_-]?key)["']?\s*[:=]\s*["'][^"'\s]{16,}["']/i],
];
function findSecrets(s) {
  const out = [];
  for (const [name, re] of SECRET_PATTERNS) { const m = s.match(re); if (m) out.push(`${name} (…${m[0].slice(-6).replace(/[^a-z0-9]/gi, '*')})`); }
  return out;
}
// Hosts that belong to a build pipeline, not to a public page.
const STAGING_RE = /\b(?:[a-z0-9-]+\.(?:pages|workers)\.dev|[a-z0-9-]+\.netlify\.app|[a-z0-9-]+\.vercel\.app|[a-z0-9-]+\.github\.io|[a-z0-9-]+\.ngrok(?:-free)?\.app|(?:staging|stage|stg|dev|test|preview|beta)\.[a-z0-9-]+\.[a-z]{2,}|localhost:\d+|127\.0\.0\.1:\d+)\b/gi;
function findStagingHosts(s) { return [...new Set([...s.matchAll(STAGING_RE)].map((m) => m[0]))]; }
// Words that describe how the security is set up. In a changelog, a version page or a doc they tell an attacker what to look for.
const SECURITY_VOCAB_RE = /\b(?:access polic(?:y|ies)|one-?time pin|otp login|oauth (?:apps?|proxy|client)|client[_ ]secret|fine-?grained (?:token|pat)|personal access token|token scopes?|api scopes?|service token|bypass rule|allowlist(?:ed)? (?:ip|email)s?|zero trust|cloudflare access|2fa enforced|rotated? (?:the )?(?:key|token|secret)|secret rotation|exposure fix|login method)\b/gi;
function findSecurityVocab(s) { return [...new Set([...s.matchAll(SECURITY_VOCAB_RE)].map((m) => m[0].toLowerCase()))]; }
// HTML comments that carry developer notes.
function findLeakyComments(html) {
  const out = [];
  for (const m of html.matchAll(/<!--([\s\S]*?)-->/g)) {
    const c = m[1];
    if (/\b(?:todo|fixme|hack|xxx|password|passwd|secret|token|api[_ -]?key|admin|staging|localhost|127\.0\.0\.1|debug|temporary|remove before|do not commit)\b/i.test(c)) out.push(c.trim().replace(/\s+/g, ' ').slice(0, 80));
  }
  return out;
}
// AI-tooling footprint. Not a vulnerability: a targeting signal. Projects visibly built with AI assistants
// are being picked as soft targets on the assumption that the code shipped unreviewed.
const AI_FILE_RE = /(^|\/)(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.claude\/.*|\.cursor\/.*|\.cursorrules|\.cursorignore|\.windsurfrules|\.windsurf\/.*|\.clinerules|\.aider[^/]*|\.github\/copilot-instructions\.md|\.github\/instructions\/.*|copilot-instructions\.md|\.codeium\/.*|\.continue\/.*|\.roo\/.*|\.roomodes|\.kiro\/.*|\.vibe\/.*|llms-ctx\.txt)$/i;
const AI_TEXT_RE = /\b(?:generated (?:with|by) (?:claude|chatgpt|gpt-?4o?|copilot|cursor|gemini|codex|windsurf|aider|devin|lovable|bolt\.new|v0\.dev)|co-authored-by:\s*(?:claude|copilot|chatgpt|gemini|cursor|codex|aider|devin)|(?:built|made|vibe-?coded|written) (?:entirely |mostly |largely )?(?:with|by|using) (?:claude|chatgpt|ai|an ai|copilot|cursor|gemini|codex|lovable|bolt\.new|v0\.dev)|🤖 generated|claude\.ai\/code\/|claude-session:|anthropic\.com\/claude-code|noreply@anthropic\.com)/i;
function findAiFootprint(s) { const m = s.match(AI_TEXT_RE); return m ? m[0] : null; }

// Comments in configuration files that are served publicly (a CMS config.yml, say). They are read by people, including the wrong ones.
function findConfigComments(text, ext) {
  const out = [];
  const lineRe = ext === '.json5' || ext === '.js' ? /^\s*\/\/(.*)$|\/\*([\s\S]*?)\*\//gm : /(?:^|\s)#(.*)$/gm; // full-line and trailing comments
  for (const m of text.matchAll(lineRe)) { const c = (m[1] ?? m[2] ?? '').trim(); if (c.length > 3) out.push(c); }
  return out;
}
function configCommentFindings(text, ext) {
  const hits = [];
  for (const c of findConfigComments(text, ext)) {
    const v = findSecurityVocab(c); const h = findStagingHosts(c); const f = opt.forbid.filter((w) => hasForbidden(c, w));
    if (v.length || h.length || f.length || /\b(private(?: repo)?|worker|proxy|token|auth|local backend|npm run|localhost|staging|password|secret|todo|fixme)\b/i.test(c)) hits.push(c.slice(0, 90));
  }
  return hits;
}
// Hardcoded CDN hosts inside JavaScript: dynamic import(), fetch(), script injection. The SRI check only sees <script src>.
const CDN_HOST_RE = /https?:\/\/(?:unpkg\.com|cdn\.jsdelivr\.net|esm\.sh|cdnjs\.cloudflare\.com|cdn\.skypack\.dev|ga\.jspm\.io|code\.jquery\.com|ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com)[^\s"'`)]*/gi;
function findCdnLoads(js) {
  const out = new Set();
  for (const m of js.matchAll(CDN_HOST_RE)) { try { const u = new URL(m[0]); out.add(u.host + u.pathname.split('/').slice(0, 2).join('/')); } catch { /* ignore */ } }
  return [...out];
}
// Does any policy's script-src admit this host?
function scriptSrcAllowsHost(policies, host) {
  return policies.some((p) => (effective(p, 'script-src-elem') || []).some((t) => t === '*' || t === 'https:' || t.includes(host) || (t.startsWith('*.') && host.endsWith(t.slice(1)))));
}

// Run the three text scanners over one text blob and report under the current section.
function checkDisclosureText(s, label, { html = false } = {}) {
  const sec = findSecrets(s);
  if (sec.length) fail('secret', `${label}: credential-shaped string(s): ${sec.join(', ')} — rotate first, then remove`);
  const hosts = findStagingHosts(s);
  if (hosts.length) warn('staging-host', `${label}: staging / preview host(s) in public output: ${hosts.slice(0, 4).join(', ')}`);
  const vocab = findSecurityVocab(s);
  if (vocab.length) warn('security-vocab', `${label}: describes the security setup (${vocab.slice(0, 4).join(', ')}) — public text should say "locked down", not how`);
  if (html) { const c = findLeakyComments(s); if (c.length) warn('html-comments', `${label}: ${c.length} developer comment(s) left in the HTML, e.g. "${c[0]}"`); }
  return sec.length + hosts.length + vocab.length;
}

// ── CSP evaluation, per the spec rather than by feel ──
// Fallback chains. frame-ancestors never falls back.
const FALLBACK = {
  'script-src-elem': ['script-src-elem', 'script-src', 'default-src'],
  'script-src-attr': ['script-src-attr', 'script-src', 'default-src'],
  'script-src': ['script-src', 'default-src'],
  'style-src-elem': ['style-src-elem', 'style-src', 'default-src'],
  'style-src-attr': ['style-src-attr', 'style-src', 'default-src'],
  'style-src': ['style-src', 'default-src'],
};
function effective(policy, directive) {
  for (const d of FALLBACK[directive] || [directive]) if (policy[d]) return policy[d];
  return null; // this policy does not govern the directive at all
}
const hashesIn = (tokens) => {
  const out = new Map(); // algo -> Set<base64>
  for (const t of tokens) { const m = /^'(sha(?:256|384|512))-([A-Za-z0-9+/=]+)'$/.exec(t); if (m) (out.get(m[1]) ?? out.set(m[1], new Set()).get(m[1])).add(m[2]); }
  return out;
};
const digest = (algo, text) => createHash(algo).update(text, 'utf8').digest('base64');
// Does ONE policy allow this inline element (script or <style>)? null tokens = not governed = allowed.
function allowsInline(tokens, body, nonceAttr) {
  if (!tokens) return true;
  const hashes = hashesIn(tokens), nonces = tokens.filter((t) => /^'nonce-/.test(t));
  if (!hashes.size && !nonces.length) return tokens.includes("'unsafe-inline'");
  // CSP2+: with hashes or nonces present, 'unsafe-inline' is ignored.
  if (nonceAttr && nonces.includes(`'nonce-${nonceAttr}'`)) return true;
  for (const [algo, set] of hashes) if (set.has(digest(algo, body))) return true;
  return false;
}
// Inline event handlers and style="" attributes: 'unsafe-inline' (when not neutralised) or 'unsafe-hashes' + hash.
function allowsInlineAttr(tokens) {
  if (!tokens) return true;
  const hasHashOrNonce = hashesIn(tokens).size || tokens.some((t) => /^'nonce-/.test(t));
  if (!hasHashOrNonce) return tokens.includes("'unsafe-inline'");
  return tokens.includes("'unsafe-hashes'"); // hashes for attributes exist but we cannot verify them statically; assume the author did it
}
// Evaluate a document against ALL policies on the response (header(s) + <meta>): content must pass every one.
function evaluateDoc(doc, policies) {
  const r = { scriptsGoverned: false, stylesGoverned: false, blockedScripts: [], blockedStyleTags: 0, styleAttrsBlocked: false, handlersBlocked: false, nonceUsed: false };
  for (const p of policies) {
    if (effective(p, 'script-src-elem')) r.scriptsGoverned = true;
    if (effective(p, 'style-src-elem') || effective(p, 'style-src-attr')) r.stylesGoverned = true;
  }
  for (const sc of doc.inlineScripts) {
    if (sc.nonce) r.nonceUsed = true;
    if (policies.some((p) => !allowsInline(effective(p, 'script-src-elem'), sc.body, sc.nonce))) r.blockedScripts.push(sc);
  }
  for (const st of doc.styleTagBodies) if (policies.some((p) => !allowsInline(effective(p, 'style-src-elem'), st.body, st.nonce))) r.blockedStyleTags++;
  if (doc.styleAttrs) r.styleAttrsBlocked = policies.some((p) => !allowsInlineAttr(effective(p, 'style-src-attr')));
  if (doc.eventHandlers) r.handlersBlocked = policies.some((p) => !allowsInlineAttr(effective(p, 'script-src-attr')));
  return r;
}
const EDGE_RE = /__CF\$cv\$params|\/cdn-cgi\/challenge-platform\/|\/cdn-cgi\/scripts\/|email-decode|__cf_email__|cloudflareinsights|rocket-loader|__cfRLUnblockHandlers/i;
// Report the evaluation under the current section.
function reportInline(doc, policies, label) {
  const ev = evaluateDoc(doc, policies);
  const n = doc.inlineScripts.length;
  if (!policies.length) info('inline-js', `${n} inline script(s), no CSP to judge them against`);
  else if (!ev.scriptsGoverned) fail('csp-script', `no policy on ${label} restricts scripts (no script-src, no default-src) — scripts are unrestricted`);
  else if (n === 0) pass('inline-js', 'no executable inline <script>');
  else if (!ev.blockedScripts.length) pass('inline-js', `${n} inline script(s), all allowed by every policy${ev.nonceUsed ? ' (nonce)' : ''}`);
  else {
    const edge = ev.blockedScripts.filter((sc) => EDGE_RE.test(sc.body)).length, own = ev.blockedScripts.length - edge;
    if (own) fail('inline-js', `${own} of ${n} inline script(s) are blocked by the CSP — no matching hash/nonce in some policy (stale hash? trailing newline changes it)`);
    if (edge) (opt.acceptEdge ? info : warn)('inline-js-edge', `${edge} inline script(s) injected at the edge by Cloudflare (JS detections / analytics / Rocket Loader) — blocked by the CSP, so it never runs; it carries a per-request token and cannot be hashed. Turn the feature off, or accept it${opt.acceptEdge ? ' (accepted)' : ' (--accept-edge-inline)'}.`);
  }
  if (doc.styleAttrs || doc.styleTags) {
    if (!policies.length || !ev.stylesGoverned) info('inline-css', `${doc.styleAttrs} style="" attribute(s), ${doc.styleTags} <style> tag(s), styles not governed by a CSP`);
    else if (ev.styleAttrsBlocked || ev.blockedStyleTags) fail('inline-css', `${ev.styleAttrsBlocked ? doc.styleAttrs + ' style="" attribute(s)' : ''}${ev.styleAttrsBlocked && ev.blockedStyleTags ? ' and ' : ''}${ev.blockedStyleTags ? ev.blockedStyleTags + ' <style> tag(s)' : ''} blocked by style-src — rendering without them`);
    else info('inline-css', `${doc.styleAttrs} style="" attribute(s), ${doc.styleTags} <style> tag(s), allowed by the policy`);
  } else pass('inline-css', 'no style="" attributes and no <style> tags');
  if (doc.eventHandlers) {
    if (ev.handlersBlocked) fail('inline-handlers', `${doc.eventHandlers} inline event handler attribute(s) (onclick=, onload= …) blocked by the CSP (hashes do not cover attributes without 'unsafe-hashes'); move them to addEventListener`);
    else warn('inline-handlers', `${doc.eventHandlers} inline event handler attribute(s) (onclick=, onload= …) — allowed, but an XSS sink; move them to addEventListener`);
  }
  return ev;
}

// Shared: evaluate one set of response headers for a document.
function checkDocHeaders(h, label, { hasMeta = false } = {}) {
  section(`Headers — ${label}`);
  // HSTS
  const hsts = h['strict-transport-security'];
  if (!hsts) fail('hsts', 'Strict-Transport-Security missing');
  else {
    const age = Number(hsts.match(/max-age=(\d+)/i)?.[1] || 0);
    if (age < 31536000) warn('hsts', `HSTS max-age is ${age}s (< 1 year)`, hsts);
    else pass('hsts', `HSTS present (${age}s${/includesubdomains/i.test(hsts) ? ', includeSubDomains' : ''}${/preload/i.test(hsts) ? ', preload' : ''})`);
    if (!/includesubdomains/i.test(hsts)) warn('hsts-sub', 'HSTS without includeSubDomains');
    if (/preload/i.test(hsts)) info('hsts-preload', 'HSTS preload is on — a one-way door: every subdomain must serve HTTPS for years. Keep it only if that was a decision.');
  }
  // CSP
  const csp = h['content-security-policy'];
  const cspRo = h['content-security-policy-report-only'];
  let d = null; const headerPolicies = [];
  if (!csp) { if (cspRo) warn('csp', 'Only a Report-Only CSP; nothing is enforced'); else fail('csp', 'Content-Security-Policy header missing'); }
  else {
    const multi = Array.isArray(csp) ? csp : csp.split(/,(?=\s*[a-z-]+-src|\s*default-src|\s*frame-ancestors|\s*base-uri|\s*object-src)/i);
    if (multi.length > 1) fail('csp-multi', `${multi.length} CSP policies on one response — browsers enforce ALL of them (the intersection). Usually a /* rule plus a path rule in _headers.`, multi.join('\n'));
    for (const m of multi) headerPolicies.push(parseCsp(m));
    d = headerPolicies[0];
    checkCspDirectives(d, 'header', { hasMeta });
  }
  // frame protection
  const xfo = h['x-frame-options'];
  if (d?.['frame-ancestors']) pass('frame', `frame-ancestors ${d['frame-ancestors'].join(' ')}`);
  else if (xfo) warn('frame', `No frame-ancestors in CSP; only X-Frame-Options: ${xfo}`);
  else fail('frame', 'No frame-ancestors and no X-Frame-Options — the site can be framed (clickjacking)');
  // simple headers
  if (/nosniff/i.test(h['x-content-type-options'] || '')) pass('nosniff', 'X-Content-Type-Options: nosniff'); else fail('nosniff', 'X-Content-Type-Options: nosniff missing');
  const rp = (h['referrer-policy'] || '').toLowerCase();
  if (!rp) warn('referrer', 'Referrer-Policy missing (browser default is strict-origin-when-cross-origin, but say it)');
  else if (['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'].includes(rp)) pass('referrer', `Referrer-Policy: ${rp}`);
  else warn('referrer', `Referrer-Policy: ${rp} leaks the full URL to other origins`);
  if (h['permissions-policy']) pass('permissions', 'Permissions-Policy present'); else warn('permissions', 'Permissions-Policy missing (camera, geolocation, microphone… stay allowed)');
  if ((h['cross-origin-opener-policy'] || '').includes('same-origin')) pass('coop', 'Cross-Origin-Opener-Policy: same-origin'); else info('coop', 'Cross-Origin-Opener-Policy not set');
  if (h['cross-origin-resource-policy']) pass('corp', `Cross-Origin-Resource-Policy: ${h['cross-origin-resource-policy']}`); else info('corp', 'Cross-Origin-Resource-Policy not set');
  checkAcao(h, 'document');
  checkDisclosure(h);
  return { d, headerPolicies };
}

function checkCspDirectives(d, where, { hasMeta = false } = {}) {
  const script = effective(d, 'script-src-elem');
  if (!script) { if (hasMeta) info('csp-script', `${where} CSP does not restrict scripts; the page's <meta> CSP is evaluated below`); else fail('csp-script', `${where} CSP has neither script-src nor default-src — scripts are unrestricted`); }
  else {
    if (script.includes("'unsafe-inline'") && !script.some((s) => /^'(nonce|sha(256|384|512))-/.test(s))) fail('csp-script', `script-src allows 'unsafe-inline' — the CSP does not stop XSS`, script.join(' '));
    else if (script.includes("'unsafe-eval'")) warn('csp-script', `script-src allows 'unsafe-eval'`, script.join(' '));
    else if (script.some((s) => s === '*' || s === 'https:' || s === 'http:' || s === 'data:')) fail('csp-script', `script-src allows any origin (${script.filter((s) => ['*', 'https:', 'http:', 'data:'].includes(s)).join(' ')})`, script.join(' '));
    else if (script.includes("'strict-dynamic'")) pass('csp-script', `script-src uses 'strict-dynamic'`);
    else pass('csp-script', `script-src ${script.join(' ')}`);
    const wild = script.filter((s) => /^https?:\/\/\*\./.test(s) || /^\*\./.test(s));
    if (wild.length) warn('csp-script-wild', `script-src has wildcard hosts: ${wild.join(' ')}`);
    const cdn = script.filter((s) => /(jsdelivr|unpkg|cdnjs|googleapis|gstatic|cloudflare\.com|jquery)/i.test(s));
    if (cdn.length) warn('csp-cdn', `script-src trusts a public CDN (${cdn.join(' ')}) — anything on that host is allowed to run. Self-host it, or pin with Subresource Integrity.`);
    const tagmgr = script.filter((s) => /(googletagmanager|google-analytics|gtm\.|segment\.(com|io)|hotjar|clarity\.ms|connect\.facebook|tiktok|snap\.licdn|cdn\.mxpnl|matomo|plausible|hs-scripts|intercom|crisp\.chat|tawk)/i.test(s));
    if (tagmgr.length) warn('csp-tagmanager', `script-src trusts a tag manager / analytics host (${tagmgr.join(' ')}) — a tag manager is remote code execution for anyone with access to the container, and it loads whatever tags are added later. Prefer a first-party proxy or a server-side setup; at minimum, lock the container's publishing rights.`);
    const thirdParty = script.filter((s) => /^https?:\/\//i.test(s) || /^[a-z0-9*.-]+\.[a-z]{2,}(:\d+)?$/i.test(s)).filter((s) => !cdn.includes(s) && !tagmgr.includes(s));
    if (thirdParty.length) info('csp-third-party', `script-src also trusts: ${thirdParty.join(' ')} — each host can run code on every page`);
  }
  const style = effective(d, 'style-src-elem');
  if (!style) { if (!hasMeta) warn('csp-style', `no style-src / default-src`); }
  else if (style.includes("'unsafe-inline'") && !hashesIn(style).size && !style.some((t) => /^'nonce-/.test(t))) info('csp-style', `style-src allows 'unsafe-inline' (CSS injection; mostly defacement — acceptable, but avoidable with zero inline styles)`);
  else if (style.includes("'unsafe-inline'")) info('csp-style', `style-src lists 'unsafe-inline' next to hashes/nonces — browsers ignore it then; style="" attributes need 'unsafe-hashes'`);
  else pass('csp-style', `style-src ${style.join(' ')}`);
  const obj = d['object-src'] ?? d['default-src'];
  if (obj?.includes("'none'")) pass('csp-object', `object-src 'none'`); else if (!hasMeta) warn('csp-object', `object-src is not 'none' (plugins / legacy <object> allowed)`);
  if (d['base-uri']) pass('csp-base', `base-uri ${d['base-uri'].join(' ')}`); else if (!hasMeta) warn('csp-base', `base-uri missing — an injected <base> can hijack every relative URL`);
  if (d['form-action']) pass('csp-form', `form-action ${d['form-action'].join(' ')}`); else if (!hasMeta) info('csp-form', `form-action not set (fine only if the site has no forms AND you accept injected forms posting anywhere)`);
  if (!d['default-src']) { if (!hasMeta) warn('csp-default', `default-src missing — every fetch directive you did not name is wide open`); }
  else if (!d['default-src'].includes("'none'") && !d['default-src'].includes("'self'")) warn('csp-default', `default-src ${d['default-src'].join(' ')}`);
  if (where === 'meta' && d['frame-ancestors']) warn('csp-meta-fa', `frame-ancestors inside a <meta> CSP is IGNORED by browsers — it must be a real header`);
  if (where === 'meta' && d['report-uri']) warn('csp-meta-ru', `report-uri inside a <meta> CSP is ignored`);
}

function checkAcao(h, label) {
  const acao = h['access-control-allow-origin'];
  if (!acao) pass('acao', `no Access-Control-Allow-Origin on ${label}`);
  else if (acao.trim() === '*') fail('acao', `Access-Control-Allow-Origin: * on ${label} — any site's JavaScript may read this response. Remove it (Pages: "! Access-Control-Allow-Origin") or set your own origin.`);
  else info('acao', `Access-Control-Allow-Origin: ${acao} on ${label}`);
}

function checkDisclosure(h) {
  const server = h['server'] || '';
  if (/\d/.test(server)) warn('server', `Server header discloses a version: ${server}`);
  else if (server) info('server', `Server: ${server}`);
  for (const k of ['x-powered-by', 'x-generator', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-drupal-cache', 'x-wix-request-id']) if (h[k]) warn('powered', `${k}: ${h[k]} — stack disclosure`);
}

// Compare a document's inline code against every policy on the response (header(s) + <meta>).
function checkInlineVsCsp(doc, headerPolicies, label) {
  section(`Inline code — ${label}`);
  const policies = [...(headerPolicies || [])];
  for (const [i, mc] of doc.metaCsps.entries()) {
    const md = parseCsp(mc);
    info('meta-csp', `page carries a <meta> CSP${doc.metaCsps.length > 1 ? ` (${i + 1}/${doc.metaCsps.length})` : ''}${headerPolicies?.length ? ' — enforced together with the header, as an intersection' : ''}`);
    checkCspDirectives(md, 'meta');
    policies.push(md);
  }
  const ev = reportInline(doc, policies, label);
  const stylePolicy = policies.map((p) => effective(p, 'style-src-elem')).find(Boolean);
  if (doc.svgInline) {
    if (doc.svgScripts) fail('svg-script', `<script> inside ${doc.svgScripts} inline <svg> — executable, and from content it is an XSS vector`);
    if (doc.svgStyles) {
      if (ev.blockedStyleTags) fail('svg-style', `<style> inside inline <svg> (${doc.svgStyles}) but style-src forbids inline styles — the SVG renders unstyled; move the rules to the stylesheet`);
      else info('svg-style', `<style> inside inline <svg> (${doc.svgStyles})`);
    }
    const ext = doc.svgRefs.filter((r) => /^https?:\/\//i.test(r));
    if (ext.length) warn('svg-ext', `inline <svg> references external resources: ${[...new Set(ext)].slice(0, 3).join(', ')}`);
  }
  if (doc.jsonldErrors.length) fail('jsonld', `${doc.jsonldErrors.length} JSON-LD block(s) do not parse`, doc.jsonldErrors.join('\n'));
  else if (doc.jsonld.length) pass('jsonld', `${doc.jsonld.length} JSON-LD block(s) parse`);
  const emailsInJsonld = findEmails(doc.jsonld.join('\n'));
  if (emailsInJsonld.length) warn('jsonld-email', `email address inside JSON-LD (${emailsInJsonld.join(', ')}) — scrapers read it, email obfuscation cannot reach inside <script>`);
  if (doc.generator) warn('generator', `stack disclosure: ${doc.generator.replace(/\s+/g, ' ')}`);
  else pass('generator', 'no <meta name="generator">');
}

// Subresource Integrity: every cross-origin script / stylesheet must be pinned.
function checkSri(doc, baseOrigin, label) {
  const cross = doc.external.filter((e) => { try { return new URL(e.url, baseOrigin || 'https://x.invalid/').origin !== (baseOrigin || 'https://x.invalid'); } catch { return false; } });
  if (!cross.length) return;
  section(`Subresource Integrity — ${label}`);
  for (const e of cross) {
    if (!e.integrity) (e.kind === 'script' ? fail : warn)('sri', `cross-origin ${e.kind} without integrity="sha384-…": ${e.url} — the host can swap it for anything; self-host it or pin it`);
    else if (!e.crossorigin) warn('sri', `${e.kind} has integrity but no crossorigin="anonymous": ${e.url} — the browser cannot verify it and blocks the load`);
    else pass('sri', `${e.kind} pinned with SRI: ${e.url}`);
  }
}

// ───────────────────────────── live mode ─────────────────────────────
const UA = 'kekkai/1.0 (+static site boundary check; read-only)';
async function get(url, { redirect = 'manual', method = 'GET' } = {}) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 15000);
  try {
    const r = await fetch(url, { method, redirect, headers: { 'user-agent': UA, 'accept': '*/*', 'cache-control': 'no-cache' }, signal: ctl.signal });
    const buf = Buffer.from(await r.arrayBuffer());
    return { status: r.status, headers: lower(Object.fromEntries(r.headers.entries())), body: buf, text: buf.toString('utf8'), url };
  } catch (e) { return { status: 0, headers: {}, body: Buffer.alloc(0), text: '', url, error: e.cause?.code || e.name || String(e) }; }
  finally { clearTimeout(t); }
}
async function follow(url, max = 6) {
  const chain = []; let r;
  for (let i = 0; i < max; i++) {
    r = await get(url); chain.push({ url, status: r.status, location: r.headers.location });
    if (r.status >= 300 && r.status < 400 && r.headers.location) { url = new URL(r.headers.location, url).href; continue; }
    break;
  }
  return { final: r, chain };
}

async function liveScan(input) {
  const u = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
  const origin = u.origin;
  section('Transport');
  // https document
  const { final: doc, chain } = await follow(u.href);
  if (doc.status === 0) { fail('fetch', `cannot fetch ${u.href}: ${doc.error}`); return; }
  if (chain.length > 1) info('redirects', `redirect chain: ${chain.map((c) => `${c.status} ${c.url}`).join(' → ')} → ${doc.status}`);
  if (doc.status !== 200) fail('status', `${u.href} answered ${doc.status}`);
  else pass('status', `${new URL(doc.url).href} 200 (${doc.body.length} bytes)`);
  const finalUrl = new URL(doc.url);
  const local = /^(localhost|127\.|0\.0\.0\.0|\[::1\]|192\.168\.|10\.)/.test(finalUrl.hostname) || finalUrl.hostname === '::1';
  const host = finalUrl.hostname;
  if (local) info('local', 'local address — transport checks (http→https, apex↔www) skipped; run again against the live domain');
  // http -> https
  const httpUrl = `http://${finalUrl.host}/`;
  if (!local) {
  const h1 = await get(httpUrl);
  if (h1.status === 0) info('http', `http://${finalUrl.host}/ not reachable (${h1.error}) — port 80 closed; fine, but check HSTS preload`);
  else if (h1.status === 301 && /^https:/i.test(h1.headers.location || '')) pass('http', `http:// → 301 → https://`);
  else if (h1.status >= 300 && h1.status < 400 && /^https:/i.test(h1.headers.location || '')) warn('http', `http:// redirects to https with ${h1.status} — use a 301`);
  else fail('http', `http://${finalUrl.host}/ answers ${h1.status} instead of redirecting to https`);
  // apex <-> www
  const other = host.startsWith('www.') ? host.slice(4) : `www.${host}`;
  const o = await get(`https://${other}/`);
  if (o.status === 0) info('alias', `https://${other}/ not reachable (${o.error}) — only one hostname serves the site`);
  else if (o.status === 301 && new URL(o.headers.location || '/', `https://${other}/`).host === host) {
    if (host.startsWith('www.')) pass('alias', `${other} → 301 → ${host}`);
    else warn('apex-primary', `${other} → 301 → ${host}: the apex is the primary host. Make www primary instead — cookies set on the apex reach every subdomain (a future staging., cms., api. inherits them), and an apex cannot be a CNAME, so CDN or failover changes need a provider that flattens it. Redirect apex → www with a 301 and keep absolute canonicals on www.`);
  }
  else if (o.status >= 300 && o.status < 400) warn('alias', `${other} redirects with ${o.status} to ${o.headers.location} — want a 301 to ${host}`);
  else if (o.status === 200) warn('alias', `https://${other}/ serves the site directly (200) — two hostnames with the same content; redirect ${host.startsWith('www.') ? other + ' → ' + host : host + ' → ' + other + ' (www as primary)'} with a 301 and keep absolute canonicals`);
  else if (!host.startsWith('www.') && o.status === 0) warn('apex-primary', `the site lives on the apex and www does not resolve — make www the primary host (cookie isolation from subdomains, CNAME-able for CDN/failover) and 301 the apex to it`);
  else info('alias', `https://${other}/ answers ${o.status}`);
  }

  const html = inspectHtml(doc.text);
  const { headerPolicies } = checkDocHeaders(doc.headers, 'document', { hasMeta: html.metaCsps.length > 0 });
  const cc = doc.headers['cache-control'] || '';
  section('Caching');
  if (/no-store/i.test(cc)) info('cache-doc', `document is no-store (${cc})`); else info('cache-doc', `document Cache-Control: ${cc || '(none)'}`);

  checkInlineVsCsp(html, headerPolicies, 'document');
  section('Document');
  if (html.canonical) {
    try { const c = new URL(html.canonical, finalUrl); if (c.host !== finalUrl.host) warn('canonical', `canonical points at another host: ${html.canonical}`); else if (!/^https?:\/\//i.test(html.canonical)) warn('canonical', `canonical is relative (${html.canonical}) — make it absolute so mirrors/previews cannot compete`); else pass('canonical', `canonical ${html.canonical}`); } catch { warn('canonical', `canonical is not a URL: ${html.canonical}`); }
  } else warn('canonical', 'no <link rel="canonical"> — a pages.dev / preview copy can compete with the real domain in search');
  const extOrigins = [...new Set(html.externalScripts.map((s) => { try { return new URL(s, finalUrl).origin; } catch { return s; } }).filter((o) => o !== finalUrl.origin))];
  checkSri(html, finalUrl.origin, 'document');
  section('Document');
  if (extOrigins.length) warn('third-party-js', `third-party scripts from: ${extOrigins.join(', ')} — each one can run anything on the page`); else pass('third-party-js', 'all scripts are same-origin');

  // assets: css, js, font
  section('Assets');
  const assetUrls = [];
  const css = html.external.find((e) => e.kind === 'stylesheet' && (() => { try { return new URL(e.url, finalUrl).origin === finalUrl.origin; } catch { return false; } })())?.url || html.external.find((e) => e.kind === 'stylesheet')?.url;
  const js = html.externalScripts.find((s) => { try { return new URL(s, finalUrl).origin === finalUrl.origin; } catch { return false; } });
  const font = doc.text.match(/<link[^>]+as\s*=\s*["']font["'][^>]*href\s*=\s*["']([^"']+)["']/i)?.[1] || doc.text.match(/href\s*=\s*["']([^"']+\.woff2?[^"']*)["']/i)?.[1];
  for (const [kind, href] of [['stylesheet', css], ['script', js], ['font', font]]) {
    if (!href) { info(`asset-${kind}`, kind === 'script' && html.inlineScripts.length ? 'no external script — scripts are inline (hashed)' : kind === 'stylesheet' && html.styleTags ? 'no external stylesheet — CSS is inlined' : `no ${kind} found in the document`); continue; }
    let au; try { au = new URL(href, finalUrl); } catch { continue; }
    if (au.origin !== finalUrl.origin) { info(`asset-${kind}`, `${kind} is cross-origin (${au.origin}) — remember its ACAO must name this origin`); continue; }
    const a = await get(au.href);
    if (a.status !== 200) { warn(`asset-${kind}`, `${kind} ${au.pathname} answered ${a.status}`); continue; }
    assetUrls.push(au);
    const ah = a.headers;
    const acc = ah['cache-control'] || '';
    const hashed = /\.[a-z0-9_-]{6,}\.(css|js|woff2?)$/i.test(au.pathname) || /[?&]v=/.test(au.search);
    if (hashed && !/immutable/i.test(acc)) info(`cache-${kind}`, `${kind} ${au.pathname} is content-hashed but not immutable (${acc || 'no Cache-Control'})`);
    else pass(`cache-${kind}`, `${kind} ${au.pathname}: ${acc || 'no Cache-Control'}`);
    checkAcao(ah, kind);
    if (au.pathname.startsWith('/cdn-cgi/')) { if (!ah['strict-transport-security']) warn(`hsts-${kind}`, `${au.pathname} is served by Cloudflare itself, not from your _headers — it has no HSTS. Turn HSTS on at the zone (SSL/TLS → Edge Certificates); includeSubDomains there covers every subdomain, so check the DNS first.`); }
    else {
      if (!ah['strict-transport-security']) warn(`hsts-${kind}`, `no HSTS on ${kind} responses (header only under document paths?)`);
      if (!/nosniff/i.test(ah['x-content-type-options'] || '')) warn(`nosniff-${kind}`, `no nosniff on ${kind}`);
    }
    if (kind === 'script' || kind === 'stylesheet') {
      const mapRef = a.text.match(/[#@]\s*sourceMappingURL\s*=\s*(\S+)/)?.[1] || ah['sourcemap'] || ah['x-sourcemap'];
      if (mapRef) {
        const mu = new URL(mapRef, au); const m = await get(mu.href);
        if (m.status === 200 && /"sources"/.test(m.text.slice(0, 2000))) fail('sourcemap', `source map is public: ${mu.pathname} — the original source (paths, comments, secrets in config) is one request away`);
        else warn('sourcemap', `${kind} references a source map (${mapRef}) that is not served — remove the comment anyway`);
      } else pass('sourcemap', `${kind} has no source map reference`);
    }
  }

  // disclosure: the document, every fetched same-origin JS/CSS, and the usual version/changelog routes
  section('Disclosure');
  let discl = checkDisclosureText(doc.text, 'document', { html: true });
  for (const au of assetUrls) { const a = await get(au.href); if (a.status === 200 && !/\.(woff2?|ttf|otf)$/i.test(au.pathname)) discl += checkDisclosureText(a.text, au.pathname); }
  for (const p of ['version', 'version.txt', 'changelog', 'changelog.txt', 'CHANGELOG.md', 'release-notes', 'humans.txt']) {
    const r = await get(`${origin}/${p}`); if (r.status !== 200) continue;
    discl += checkDisclosureText(r.text, `/${p}`, { html: /html/i.test(r.headers['content-type'] || '') });
    if (findSecurityVocab(r.text).length || findStagingHosts(r.text).length) warn('changelog', `/${p} is public even with noindex — write security-related entries neutrally ("housekeeping", "updated project notes")`);
  }
  if (!discl) pass('disclosure', 'no credential shapes, staging hosts or security-setup vocabulary in the document, its assets or version/changelog routes');
  for (const au of assetUrls.filter((u) => /\.m?js$/i.test(u.pathname))) { const a = await get(au.href); const loads = findCdnLoads(a.text); if (loads.length) warn('js-cdn', `${au.pathname} references a public CDN at runtime (${loads.slice(0, 3).join(', ')}) — not visible to the SRI check; vendor it`); }
  if (opt.admin) {
    section('CMS');
    const ai = await get(`${origin}/${opt.admin}/`);
    if (ai.status !== 200) info('cms', `/${opt.admin}/ answers ${ai.status}`);
    else {
      const ah = ai.headers;
      if (!/no-store/i.test(ah['cache-control'] || '')) warn('cms-cache', `/${opt.admin}/ is cacheable (${ah['cache-control'] || 'no Cache-Control'}) — the admin should be no-store`);
      if (!/noindex/i.test(ah['x-robots-tag'] || '') && !/noindex/i.test(ai.text)) warn('cms-index', `/${opt.admin}/ carries no noindex (header or meta)`);
      if (!ah['content-security-policy']) fail('cms-csp', `/${opt.admin}/ has no CSP header`);
      const adoc = inspectHtml(ai.text);
      const cross = adoc.external.filter((e) => { try { return new URL(e.url, finalUrl).origin !== finalUrl.origin; } catch { return false; } });
      if (cross.length) fail('cms-cdn', `the admin page loads ${cross.length} cross-origin resource(s) (${cross.slice(0, 2).map((e) => e.url).join(', ')}) — whoever controls that host controls your publishing pipeline; self-host the bundle`);
      else pass('cms-bundle', 'admin page loads only same-origin code');
      for (const cfg of ['config.yml', 'config.yaml', 'config.json']) {
        const r = await get(`${origin}/${opt.admin}/${cfg}`); if (r.status !== 200) continue;
        const hits = configCommentFindings(r.text, extname(cfg));
        if (hits.length) warn('cms-config-comments', `/${opt.admin}/${cfg}: ${hits.length} comment(s) that describe the setup, e.g. "${hits[0]}" — public file; strip comments at build`); else pass('cms-config', `/${opt.admin}/${cfg}: no telling comments`);
        const repo = r.text.match(/repo:\s*([^\s#]+)/)?.[1]; if (repo) info('cms-repo', `config names the content repository ${repo} — fine only while that repo is private`);
        break;
      }
    }
  }
  section('AI footprint');
  const aiHits = [];
  const aiDoc = findAiFootprint(doc.text); if (aiDoc) aiHits.push(`document ("${aiDoc}")`);
  if (/<meta[^>]+generator[^>]+(?:claude|chatgpt|copilot|cursor|lovable|bolt|v0)/i.test(doc.text)) aiHits.push('generator meta names an AI tool');
  for (const p of ['humans.txt', 'CLAUDE.md', 'AGENTS.md', '.cursorrules', 'llms-ctx.txt']) { const r = await get(`${origin}/${p}`); if (r.status === 200 && r.body.length && (p === 'humans.txt' ? findAiFootprint(r.text) : !/html/i.test(r.headers['content-type'] || ''))) aiHits.push(`/${p} is served`); }
  if (aiHits.length) warn('ai-footprint', `the site advertises that it was built with an AI assistant: ${aiHits.join(', ')} — projects that visibly ship AI-written code are being picked as soft targets; keep the credit out of public output (guide PART 7.6)`);
  else pass('ai-footprint', 'no AI-assistant attribution in public output');

  // SVG files referenced by the document (as <img>/<object>/<use>): scripts inside them run when embedded as <object>/inline
  const svgSeen = new Set();
  for (const ref of html.svgRefs) {
    let su; try { su = new URL(ref, finalUrl); } catch { continue; }
    if (su.origin !== finalUrl.origin || svgSeen.has(su.pathname) || svgSeen.size >= 5) continue;
    svgSeen.add(su.pathname);
    const r = await get(su.href); if (r.status !== 200) continue;
    svgFileChecks(r.text, su.pathname);
  }

  // robots / sitemap / feeds / text files
  section('Public text files');
  const robots = await get(`${origin}/robots.txt`);
  if (robots.status === 200) {
    const lines = robots.text.split(/\r?\n/);
    const dis = lines.filter((l) => /^\s*disallow\s*:\s*\S/i.test(l));
    const adminish = dis.filter((l) => /(^|\/)(admin|administrator|cms|login|signin|wp-admin|wp-login\.php|backend|dashboard|private|internal|staging|_admin|manage)(\/|$)/i.test(l.replace(/^\s*disallow\s*:\s*/i, '')) || /(^|\/)(secret|dev|wp-[a-z]+)(\/|$)/i.test(l.replace(/^\s*disallow\s*:\s*/i, '')));
    if (adminish.length) fail('robots-admin', `robots.txt advertises a private path: ${adminish.map((l) => l.trim()).join(' | ')} — robots.txt is public; hide the path with an unguessable name + noindex header instead`);
    else if (dis.length) info('robots-disallow', `robots.txt disallows: ${dis.map((l) => l.trim()).join(' | ')} (every Disallow names a path to the world)`);
    else pass('robots', 'robots.txt names no private paths');
    if (/content-signal/i.test(robots.text)) warn('robots-managed', 'a managed block (Content-Signal) sits in robots.txt — your host prepended it; decide whether you want it');
    const sm = lines.find((l) => /^\s*sitemap\s*:/i.test(l));
    if (sm) info('robots-sitemap', sm.trim());
  } else info('robots', `robots.txt answers ${robots.status}`);
  const smUrl = (robots.text.match(/^\s*sitemap\s*:\s*(\S+)/im)?.[1]) || `${origin}/sitemap-index.xml`;
  let pageUrls = [];
  for (const cand of [smUrl, `${origin}/sitemap-index.xml`, `${origin}/sitemap.xml`, `${origin}/sitemap-0.xml`]) {
    const s = await get(cand); if (s.status !== 200) continue;
    let locs = [...s.text.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)].map((m) => m[1]);
    if (/<sitemapindex/i.test(s.text)) { const first = locs[0] ? origin + new URL(locs[0]).pathname : ''; const sub = await get(first); locs = [...sub.text.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)].map((m) => m[1]); }
    const bad = locs.filter((l) => /(^|\/)(admin|administrator|cms|login|signin|wp-admin|wp-login\.php|backend|dashboard|private|internal|staging|_admin|manage)(\/|$)/i.test(new URL(l).pathname));
    if (bad.length) fail('sitemap-admin', `sitemap lists private-looking URLs: ${bad.slice(0, 5).join(', ')}`); else pass('sitemap', `sitemap ok (${locs.length} URLs from ${new URL(cand).pathname})`);
    const foreign = locs.filter((l) => { try { return new URL(l).host !== host; } catch { return true; } });
    if (foreign.length && !local) warn('sitemap-host', `${foreign.length} sitemap URL(s) on another host, e.g. ${foreign[0]}`);
    pageUrls = locs; break;
  }
  for (const f of ['llms.txt', 'sitemap.xml', 'sitemap-index.xml', 'rss.xml', 'feed.xml', 'atom.xml', 'humans.txt', '.well-known/security.txt', 'version.txt']) {
    const r = await get(`${origin}/${f}`); if (r.status !== 200) continue;
    const em = findEmails(r.text);
    if (em.length && f !== '.well-known/security.txt' && f !== 'humans.txt') warn('txt-email', `/${f} contains an email address (${em.join(', ')}) — harvesters read text files, obfuscation cannot reach them`);
    if (f === '.well-known/security.txt') info('security-txt', `/.well-known/security.txt present${em.length ? ` (${em[0]})` : ''}`);
    if (f === 'version.txt') { info('version', `/version.txt: ${r.text.trim().split('\n')[0]} (${/no-store/i.test(r.headers['cache-control'] || '') ? 'no-store' : 'CACHEABLE — make it no-store so it can never answer stale'})`); }
  }

  // probes
  if (opt.probe) {
    section('Things that must not be served');
    const rnd = await get(`${origin}/kekkai-${Date.now().toString(36)}-does-not-exist/`);
    const soft404 = rnd.status === 200;
    if (soft404) warn('soft-404', 'a random URL answers 200 (SPA fallback / soft 404) — probes below compare bodies, results are weaker');
    else pass('404', `random URL answers ${rnd.status}`);
    const probes = ['.git/HEAD', '.git/config', '.env', '.env.production', 'package.json', 'package-lock.json', 'astro.config.mjs', 'tsconfig.json', 'wrangler.toml', 'netlify.toml', '.DS_Store', 'server-status', 'phpinfo.php', 'wp-login.php', 'xmlrpc.php', 'admin/', 'wp-admin/', 'cms/', '.vscode/settings.json', 'config.json', '_headers', '_redirects', 'functions/', 'src/', 'node_modules/'];
    let hits = 0;
    for (const p of probes) {
      const r = await get(`${origin}/${p}`);
      if (r.status !== 200) continue;
      if (soft404 && r.body.equals(rnd.body)) continue;
      const ct = (r.headers['content-type'] || '').split(';')[0];
      if (/^(admin|wp-admin|cms)\/$/.test(p) && /html/.test(ct) && !/sign in|login|password|admin|cms|netlify-cms|decap|sveltia|tina|keystatic/i.test(r.text)) continue; // generic page, not an admin
      hits++; fail('probe', `/${p} is served (200, ${ct || 'unknown type'}, ${r.body.length} bytes)`);
    }
    if (!hits) pass('probe', `${probes.length} well-known leak paths all refused`);
  }

  // sample inner pages
  if (opt.pages > 0 && pageUrls.length) {
    section('Inner pages');
    // sample by path on the scanned origin, so a local preview of a sitemap that names the real domain still works
    const sample = [...new Set(pageUrls.map((l) => { try { return origin + new URL(l).pathname; } catch { return null; } }).filter(Boolean))].filter((l) => l !== finalUrl.href && l !== `${origin}/`).slice(0, opt.pages);
    const policies = new Map(); let scannedPages = 0, redirected = 0;
    for (let l of sample) {
      let r = await get(l), hops = 0;
      while (r.status >= 300 && r.status < 400 && r.headers.location && hops < 3) {
        const next = new URL(r.headers.location, l);
        if (next.origin !== origin) break;
        redirected++; info('page-redirect', `${new URL(l).pathname} → ${r.status} → ${next.pathname}${r.status === 307 || r.status === 302 ? ' (temporary; a canonical URL change wants a 301)' : ''}`);
        l = next.href; r = await get(l); hops++;
      }
      if (r.status !== 200) { warn('page', `${l} → ${r.status}`); continue; }
      scannedPages++;
      const h = r.headers; const csp = h['content-security-policy'];
      if (!csp && !/http-equiv\s*=\s*["']content-security-policy/i.test(r.text)) fail('page-csp', `${new URL(l).pathname} has NO CSP (neither header nor <meta>; route missing from the headers path list?)`);
      else if (csp) policies.set(csp, (policies.get(csp) || []).concat(new URL(l).pathname));
      if (!h['strict-transport-security']) fail('page-hsts', `${new URL(l).pathname} has no HSTS`);
      const ih = inspectHtml(r.text);
      const pols = [...(csp ? csp.split(/,(?=\s*[a-z-]+-src|\s*default-src|\s*frame-ancestors)/i).map(parseCsp) : []), ...ih.metaCsps.map(parseCsp)];
      if (!csp && !ih.metaCsps.length) { /* already reported above */ }
      else {
        const pev = evaluateDoc(ih, pols);
        const own = pev.blockedScripts.filter((sc) => !EDGE_RE.test(sc.body)).length;
        if (!pev.scriptsGoverned) fail('page-csp', `${new URL(l).pathname}: no policy restricts scripts`);
        if (own) fail('page-inline', `${new URL(l).pathname}: ${own} inline script(s) blocked by its CSP`);
        if (pev.styleAttrsBlocked || pev.blockedStyleTags) fail('page-inline-css', `${new URL(l).pathname}: inline styles blocked by style-src`);
      }
      if (ih.jsonldErrors.length) fail('page-jsonld', `${new URL(l).pathname}: JSON-LD does not parse`);
    }
    if (policies.size > 1) info('page-policies', `${policies.size} distinct CSPs across sampled pages (fine if intentional: docs vs text mirror vs admin)`);
    if (redirected) warn('sitemap-redirects', `${redirected} of ${sample.length} sampled sitemap URL(s) redirect — the sitemap should list the final URLs (trailing slash included); crawlers follow, but it costs a request per page and dilutes canonicals`);
    if (!scannedPages) info('pages', `no inner page could be scanned (${sample.length} sampled)`);
    else if (results.filter((r) => r.section === 'Inner pages' && r.level === 'fail').length === 0) pass('pages', `${scannedPages} inner page(s): CSP + HSTS present, inline code consistent`);
  }
}

function svgFileChecks(svg, label) {
  section('SVG files');
  if (/<script\b/i.test(svg)) fail('svg-file-script', `${label} contains <script> — runs when the SVG is embedded as <object>/<iframe> or inlined; strip it`);
  const handlers = (svg.match(/\son[a-z]+\s*=\s*["']/gi) || []).length;
  if (handlers) fail('svg-file-handlers', `${label} has ${handlers} inline event handler(s)`);
  if (/<foreignObject\b/i.test(svg)) warn('svg-foreign', `${label} uses <foreignObject> (arbitrary HTML inside the SVG)`);
  const ext = [...svg.matchAll(/(?:xlink:)?href\s*=\s*["'](https?:\/\/[^"']+)["']/gi)].map((m) => m[1]);
  if (ext.length) warn('svg-file-ext', `${label} references external URLs: ${[...new Set(ext)].slice(0, 3).join(', ')}`);
  if (/<style\b/i.test(svg)) info('svg-file-style', `${label} has <style> — fine as <img>, hits style-src when inlined or used as <object>`);
  if (!/<script\b|<foreignObject\b/i.test(svg) && !handlers && !ext.length) pass('svg-file', `${label} clean`);
}

// ───────────────────────────── dist mode ─────────────────────────────
function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p)); else out.push(p);
  }
  return out;
}
function parseHeadersFile(text) {
  const rules = []; // { pattern, set: {k:v[]}, unset: [k] }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    if (!/^\s/.test(line)) { rules.push({ pattern: line.trim(), set: {}, unset: [] }); continue; }
    if (!rules.length) continue;
    const t = line.trim();
    if (t.startsWith('!')) { rules[rules.length - 1].unset.push(t.slice(1).trim().toLowerCase()); continue; }
    const i = t.indexOf(':'); if (i < 0) continue;
    const k = t.slice(0, i).trim().toLowerCase(), v = t.slice(i + 1).trim();
    (rules[rules.length - 1].set[k] ||= []).push(v);
  }
  return rules;
}
function matchPattern(path, pattern) {
  // Cloudflare/Netlify: `*` matches any chars, `:name` a segment. Also match the directory form of index.html.
  const re = new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/:[a-zA-Z0-9_]+/g, '[^/]+') + '$');
  const cands = [path];
  if (path.endsWith('/index.html')) cands.push(path.slice(0, -'index.html'.length));
  return cands.some((c) => re.test(c));
}
function effectiveHeaders(path, rules) {
  const h = {};
  for (const r of rules) {
    if (!matchPattern(path, r.pattern)) continue;
    for (const k of r.unset) delete h[k];
    for (const [k, vs] of Object.entries(r.set)) (h[k] ||= []).push(...vs);
  }
  // multiple CSP values stay an array so checkDocHeaders can flag them
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k, v.length > 1 && k !== 'content-security-policy' ? v.join(', ') : (v.length === 1 ? v[0] : v)]));
}

let _rulesCache = null;
function rulesFor(dir) { if (_rulesCache) return _rulesCache; const hf = join(dir, '_headers'); _rulesCache = existsSync(hf) ? parseHeadersFile(readFileSync(hf, 'utf8')) : []; return _rulesCache; }
function distScan(dir) {
  const files = walk(dir).map((f) => ({ abs: f, rel: '/' + relative(dir, f).split(sep).join('/') }));
  section('Build output');
  info('files', `${files.length} files under ${dir}`);
  const maps = files.filter((f) => f.rel.endsWith('.map'));
  if (maps.length) fail('sourcemap', `${maps.length} source map(s) in the output: ${maps.slice(0, 5).map((f) => f.rel).join(', ')}`); else pass('sourcemap', 'no source maps');
  const mapRefs = files.filter((f) => /\.(js|mjs|css)$/.test(f.rel) && /[#@]\s*sourceMappingURL=/.test(readFileSync(f.abs, 'utf8')));
  if (mapRefs.length) warn('sourcemap-ref', `${mapRefs.length} file(s) still reference a sourceMappingURL: ${mapRefs.slice(0, 3).map((f) => f.rel).join(', ')}`);
  const junk = files.filter((f) => /(^|\/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|\.env[^/]*|[^/]*\.config\.(mjs|cjs|js|ts)|tsconfig\.json|wrangler\.toml|netlify\.toml|\.DS_Store|Thumbs\.db|\.git\/.*|\.gitignore|README\.md)$/i.test(f.rel));
  if (junk.length) fail('junk', `build/config files in the output: ${junk.slice(0, 8).map((f) => f.rel).join(', ')}`); else pass('junk', 'no config, lock, env or git files');
  const text = files.filter((f) => TEXT_EXT.has(extname(f.rel).toLowerCase()) || f.rel === '/_headers' || f.rel === '/_redirects');
  const read = (f) => readFileSync(f.abs, 'utf8');

  // local paths, forbidden strings, admin dir leak
  const pathHits = new Map();
  for (const f of text) {
    if (f.rel === '/_headers') continue;
    const s = read(f);
    for (const m of s.matchAll(/(\/home\/([a-z0-9_-]+)\/|\/Users\/([A-Za-z0-9_-]+)\/|[A-Z]:\\Users\\([A-Za-z0-9_-]+)\\)/g)) {
      const user = (m[2] || m[3] || m[4] || '').toLowerCase();
      if (/^(x|xx|you|me|user|username|name|yourname|your-name|someone|example|foo|bar|\$\{?.*)$/.test(user) || user.length < 3) continue; // documentation placeholders
      pathHits.set(m[1], f.rel);
    }
  }
  if (pathHits.size) fail('local-paths', `local filesystem paths in the output: ${[...pathHits].map(([p, f]) => `${p} (${f})`).slice(0, 5).join(', ')}`); else pass('local-paths', 'no local filesystem paths');
  if (opt.forbid.length) {
    const hits = [];
    for (const f of text) { const s = read(f); for (const w of opt.forbid) if (hasForbidden(s, w)) hits.push(`${w} in ${f.rel}`); }
    if (hits.length) fail('forbid', `forbidden strings found: ${hits.slice(0, 10).join('; ')}`); else pass('forbid', `none of ${opt.forbid.length} forbidden string(s) appear`);
  }
  if (opt.admin) {
    const leaks = text.filter((f) => !f.rel.startsWith(`/${opt.admin}/`) && f.rel !== '/_headers' && read(f).includes(opt.admin)).map((f) => f.rel);
    if (leaks.length) fail('admin-leak', `the admin folder name appears outside its folder: ${leaks.slice(0, 5).join(', ')}`); else pass('admin-leak', 'admin folder name appears only inside itself and _headers');
    if (!existsSync(join(dir, opt.admin))) warn('admin-dir', `--admin ${opt.admin} but no such folder in the output`);
  }
  const forges = new Map();
  for (const f of text) { if (f.rel === '/_headers' || (opt.admin && f.rel.startsWith(`/${opt.admin}/`))) continue; for (const m of read(f).matchAll(/https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?)/g)) forges.set(`${m[1]}/${m[2]}`, f.rel); }
  if (forges.size) info('forge', `repository links in the output (fine for public release repos, a leak for the site's own): ${[...forges.keys()].slice(0, 8).join(', ')}`);

  // disclosure over every text file
  section('Disclosure');
  let discl = 0, scanned = 0;
  for (const f of text) {
    if (f.rel === '/_headers' || f.rel === '/_redirects' || (opt.admin && f.rel.startsWith(`/${opt.admin}/`))) continue;
    scanned++; discl += checkDisclosureText(read(f), f.rel, { html: /\.html?$/.test(f.rel) });
  }
  if (!discl) pass('disclosure', `${scanned} text file(s): no credential shapes, staging hosts or security-setup vocabulary`);
  // comments in publicly served config files (the --admin folder included: its config.yml is public)
  const cfgFiles = files.filter((f) => /\.(ya?ml|toml|json5|ini|cfg|conf)$/i.test(f.rel));
  let cfgHits = 0;
  for (const f of cfgFiles) { const hits = configCommentFindings(read(f), extname(f.rel).toLowerCase()); if (hits.length) { cfgHits++; warn('config-comments', `${f.rel}: ${hits.length} comment(s) that describe the setup, e.g. "${hits[0]}" — this file is served to everyone; strip comments at build`); } }
  if (cfgFiles.length && !cfgHits) pass('config-comments', `${cfgFiles.length} served config file(s) carry no telling comments`);
  // CDN loads hidden inside JavaScript
  const jsFiles = files.filter((f) => /\.m?js$/i.test(f.rel));
  const distPolicies = [];
  for (const f of files.filter((f) => /\.html?$/.test(f.rel))) { const h = effectiveHeaders(f.rel, rulesFor(dir)); if (h['content-security-policy']) for (const c of [].concat(h['content-security-policy'])) distPolicies.push(parseCsp(c)); for (const mc of inspectHtml(read(f)).metaCsps) distPolicies.push(parseCsp(mc)); }
  let cdnHits = 0;
  for (const f of jsFiles) {
    const loads = findCdnLoads(read(f)); if (!loads.length) continue; cdnHits++;
    const allowed = loads.filter((l) => scriptSrcAllowsHost(distPolicies, l.split('/')[0]));
    if (allowed.length) fail('js-cdn', `${f.rel} loads code from a public CDN at runtime (${allowed.slice(0, 3).join(', ')}) and the CSP lets it run — whoever controls that host controls this page; vendor it`);
    else warn('js-cdn', `${f.rel} references a public CDN at runtime (${loads.slice(0, 3).join(', ')}) — the CSP blocks it, so that feature breaks; vendor it or allow it on purpose`);
  }
  if (jsFiles.length && !cdnHits) pass('js-cdn', `${jsFiles.length} script file(s): no runtime loads from public CDNs`);
  section('AI footprint');
  const aiFiles = files.filter((f) => AI_FILE_RE.test(f.rel)).map((f) => f.rel);
  const aiText = [];
  for (const f of text) { if (f.rel === '/_headers' || (opt.admin && f.rel.startsWith(`/${opt.admin}/`))) continue; const m = findAiFootprint(read(f)); if (m) aiText.push(`${f.rel} ("${m}")`); if (aiText.length >= 5) break; }
  if (aiFiles.length || aiText.length) warn('ai-footprint', `AI-assistant footprint in the output: ${[...aiFiles, ...aiText].slice(0, 6).join(', ')} — a targeting signal; strip it from what ships (guide PART 7.6)`);
  else pass('ai-footprint', 'no AI-assistant attribution or config files in the output');
  section('Build output');

  // emails in non-HTML text files and inside <script>
  const emailFiles = [];
  for (const f of text) {
    const s = read(f);
    if (/\.html?$/.test(f.rel)) { for (const m of s.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) if (findEmails(m[1]).length) { emailFiles.push(f.rel + ' (inside <script>)'); break; } }
    else if (f.rel !== '/_headers' && !/security\.txt$|humans\.txt$/.test(f.rel) && findEmails(s, { skipLicense: true }).length) emailFiles.push(f.rel);
  }
  if (emailFiles.length) warn('email', `email addresses where obfuscation cannot reach: ${emailFiles.slice(0, 6).join(', ')}`); else pass('email', 'no email addresses in text files or inside <script>');

  // _headers
  section('_headers');
  const hf = files.find((f) => f.rel === '/_headers');
  const rules = hf ? parseHeadersFile(read(hf)) : [];
  if (!hf) warn('headers-file', 'no _headers file — security headers must then come from the host dashboard / a worker; live scan will tell');
  else {
    pass('headers-file', `_headers with ${rules.length} rule block(s)`);
    const cspUnderStar = rules.find((r) => r.pattern === '/*' && r.set['content-security-policy']);
    const cspElsewhere = rules.filter((r) => r.pattern !== '/*' && r.set['content-security-policy']);
    if (cspUnderStar && cspElsewhere.length) fail('csp-star', `a CSP under /* AND under ${cspElsewhere.map((r) => r.pattern).join(', ')} — rules are additive, those paths get TWO policies (the intersection)`);
    if (existsSync(join(dir, 'public', '_headers'))) warn('headers-two', 'public/_headers next to a generated _headers — two sources of truth');
  }
  const htmls = files.filter((f) => /\.html?$/.test(f.rel));
  const noCsp = [], seen = new Map();
  for (const f of htmls) {
    const h = effectiveHeaders(f.rel, rules);
    const doc = inspectHtml(read(f));
    if (!h['content-security-policy'] && doc.metaCsp === null) { noCsp.push(f.rel); continue; }
    const key = JSON.stringify([h['content-security-policy'], h['strict-transport-security'], h['x-frame-options'], h['x-content-type-options'], h['referrer-policy'], h['permissions-policy'], h['cross-origin-opener-policy'], h['cross-origin-resource-policy'], h['access-control-allow-origin']]);
    if (!seen.has(key)) seen.set(key, { h, docs: [], pages: [] });
    seen.get(key).pages.push(f.rel); seen.get(key).docs.push(doc);
  }
  if (noCsp.length) fail('csp-coverage', `${noCsp.length} HTML file(s) matched by NO CSP rule (new route not in the path list?): ${noCsp.slice(0, 6).join(', ')}`);
  else if (htmls.length) pass('csp-coverage', `every one of ${htmls.length} HTML file(s) gets a CSP`);
  let g = 0;
  for (const [, grp] of seen) {
    g++;
    const label = `${grp.pages.length} page(s) e.g. ${grp.pages[0]}`;
    const anyMeta = grp.docs.some((doc) => doc.metaCsps.length);
    const { headerPolicies } = checkDocHeaders(grp.h, label, { hasMeta: anyMeta });
    // inline code across the group: every page evaluated against header policies + its own <meta> policies (intersection)
    const totals = { inline: 0, own: 0, edge: 0, styleAttrs: 0, styleTags: 0, cssBlockedPages: 0, jsonldErr: 0, gen: 0, pages: new Set(), ungoverned: 0, metaSeen: new Set() };
    for (const [i, doc] of grp.docs.entries()) {
      const pols = [...headerPolicies, ...doc.metaCsps.map(parseCsp)];
      for (const mc of doc.metaCsps) totals.metaSeen.add(mc.replace(/'sha(256|384|512)-[A-Za-z0-9+/=]+'/g, "'sha…'"));
      const ev = evaluateDoc(doc, pols);
      if (pols.length && !ev.scriptsGoverned) totals.ungoverned++;
      totals.inline += doc.inlineScripts.length;
      for (const sc of ev.blockedScripts) { if (EDGE_RE.test(sc.body)) totals.edge++; else { totals.own++; totals.pages.add(grp.pages[i]); } }
      totals.styleAttrs += doc.styleAttrs; totals.styleTags += doc.styleTags; if (ev.styleAttrsBlocked || ev.blockedStyleTags) totals.cssBlockedPages++;
      totals.jsonldErr += doc.jsonldErrors.length; if (doc.generator) totals.gen++;
    }
    section(`Inline code — ${label}`);
    if (totals.metaSeen.size) { info('meta-csp', `${totals.metaSeen.size} distinct <meta> CSP shape(s) across these pages (hashes elided)`); for (const mc of [...totals.metaSeen].slice(0, 1)) checkCspDirectives(parseCsp(mc), 'meta'); }
    if (totals.ungoverned) fail('csp-script', `${totals.ungoverned} page(s) where no policy restricts scripts`);
    if (!totals.inline) pass('inline-js', 'no executable inline <script> in this group');
    else if (totals.own) fail('inline-js', `${totals.own} of ${totals.inline} inline script(s) are blocked by the CSP (no matching hash/nonce in some policy; stale hash?) — e.g. ${[...totals.pages].slice(0, 3).join(', ')}`);
    else pass('inline-js', `${totals.inline} inline script(s), all allowed by every policy`);
    if (totals.cssBlockedPages) fail('inline-css', `inline styles blocked by style-src on ${totals.cssBlockedPages} page(s) (${totals.styleAttrs} style="" attribute(s), ${totals.styleTags} <style> tag(s) in the group)`);
    else if (totals.styleAttrs || totals.styleTags) info('inline-css', `${totals.styleAttrs} style="" attribute(s), ${totals.styleTags} <style> tag(s), allowed by the policy`);
    else pass('inline-css', 'no inline styles');
    if (totals.jsonldErr) fail('jsonld', `${totals.jsonldErr} JSON-LD block(s) do not parse`); else pass('jsonld', 'JSON-LD parses');
    const handlers = grp.docs.reduce((n, doc) => n + doc.eventHandlers, 0);
    if (handlers) { const blocked = grp.docs.some((doc) => doc.eventHandlers && evaluateDoc(doc, [...headerPolicies, ...doc.metaCsps.map(parseCsp)]).handlersBlocked); (blocked ? fail : warn)('inline-handlers', `${handlers} inline event handler attribute(s) (onclick=, onload= …) across the group — ${blocked ? 'blocked by the CSP' : 'allowed, but an XSS sink'}; move them to addEventListener`); }
    const svgS = grp.docs.reduce((n, doc) => n + doc.svgScripts, 0), svgC = grp.docs.reduce((n, doc) => n + doc.svgStyles, 0);
    if (svgS) fail('svg-script', `<script> inside inline <svg> on ${svgS} occurrence(s)`);
    if (svgC && totals.cssBlockedPages) fail('svg-style', `<style> inside inline <svg> (${svgC}) on pages whose style-src blocks inline styles`);
    const svgExt = [...new Set(grp.docs.flatMap((doc) => doc.svgRefs).filter((r) => /^https?:\/\//i.test(r)))];
    if (svgExt.length) warn('svg-ext', `inline <svg> references external resources: ${svgExt.slice(0, 3).join(', ')}`);
    const merged = { external: grp.docs.flatMap((doc) => doc.external) };
    merged.external = [...new Map(merged.external.map((e) => [e.url, e])).values()];
    checkSri(merged, '', label);
    if (totals.gen) warn('generator', `<meta name="generator"> on ${totals.gen} page(s) — stack disclosure`); else pass('generator', 'no generator meta');
  }
  if (g > 1) info('groups', `${g} distinct header profiles across the HTML files (fine when intentional: documents / text mirror / admin)`);
  // svg files
  const svgs = files.filter((f) => f.rel.endsWith('.svg'));
  let svgBad = 0;
  for (const f of svgs) { const before = results.length; svgFileChecks(read(f), f.rel); if (results.slice(before).some((r) => r.level !== 'pass')) svgBad++; else results.splice(before); }
  if (svgs.length) { section('SVG files'); (svgBad ? info : pass)('svg-files', `${svgs.length} SVG file(s) scanned, ${svgBad} with findings`); }

  // _redirects
  const rf = files.find((f) => f.rel === '/_redirects');
  if (rf) {
    section('_redirects');
    const lines = read(rf).split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    let bad = 0;
    for (const l of lines) {
      const [from, to, status = '301'] = l.split(/\s+/);
      if (!from || !to) continue;
      const code = status.replace('!', '');
      const splatTo = /:splat|\*/.test(to) && /^https?:\/\/[^/]*(:splat|\*)/i.test(to);
      if (splatTo || /^(https?:)?\/\/\*/.test(to) || to === ':splat' || to === '*') { bad++; fail('redirect-open', `open redirect: "${from} → ${to}" — the destination host comes from the request`); continue; }
      if (/^https?:\/\//i.test(to) && /(staging|stage|dev\.|test\.|localhost|127\.0\.0\.1|\.pages\.dev|\.netlify\.app|\.workers\.dev|\.vercel\.app|ngrok)/i.test(to)) { bad++; warn('redirect-staging', `"${from} → ${to}" points at a staging / preview host`); continue; }
      if (code === '200' && /^https?:\/\//i.test(to)) { bad++; info('redirect-proxy', `"${from} → ${to} 200" proxies another origin (names the upstream; Pages ignores it, Netlify serves it)`); continue; }
      if (/(^|\/)(admin|administrator|cms|login|signin|wp-admin|wp-login\.php|backend|dashboard|private|internal|staging|_admin|manage)(\/|$)/i.test(from)) { bad++; info('redirect-admin', `"${from}" names a private-looking path in a public-ish file`); }
      if (!/^\//.test(from)) { bad++; warn('redirect-host', `"${from}" is not a path — _redirects cannot match hostnames on Pages; use a Redirect Rule`); }
    }
    if (!bad) pass('redirects', `_redirects: ${lines.length} rule(s), no open redirects, staging hosts or proxies`);
  }

  // robots in dist
  section('Public text files');
  const robots = files.find((f) => f.rel === '/robots.txt');
  if (robots) {
    const dis = read(robots).split(/\r?\n/).filter((l) => /^\s*disallow\s*:\s*\S/i.test(l));
    const adminish = dis.filter((l) => /(^|\/)(admin|administrator|cms|login|signin|wp-admin|wp-login\.php|backend|dashboard|private|internal|staging|_admin|manage)(\/|$)/i.test(l.replace(/^\s*disallow\s*:\s*/i, '')) || /(^|\/)(secret|dev|wp-[a-z]+)(\/|$)/i.test(l.replace(/^\s*disallow\s*:\s*/i, '')));
    if (adminish.length) fail('robots-admin', `robots.txt advertises a private path: ${adminish.map((l) => l.trim()).join(' | ')}`);
    else if (dis.length) info('robots-disallow', `robots.txt disallows: ${dis.map((l) => l.trim()).join(' | ')}`);
    else pass('robots', 'robots.txt names no private paths');
  } else info('robots', 'no robots.txt in the output');
  if (!files.some((f) => /^\/sitemap(-index|-0)?\.xml$/.test(f.rel))) info('sitemap', 'no sitemap in the output');
  const wk = files.filter((f) => f.rel.startsWith('/.well-known/'));
  if (wk.length) info('well-known', `.well-known: ${wk.map((f) => f.rel).join(', ')}`);
  const vt = files.find((f) => f.rel === '/version.txt');
  if (vt) { const h = effectiveHeaders('/version.txt', rules); info('version', `/version.txt present (${/no-store/i.test(h['cache-control'] || '') ? 'no-store' : 'CACHEABLE — add Cache-Control: no-store'})`); }
  else info('version', 'no /version.txt build fingerprint — add one so "is the new build live?" has a one-request answer');
}

// ───────────────────────────── repo mode ─────────────────────────────
function git(dir, args, { maxBuffer = 64 * 1024 * 1024, okStatus = [0] } = {}) {
  try { return execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer }); }
  catch (e) { return okStatus.includes(e.status) ? (e.stdout || '') : null; }
}
function repoScan(dir) {
  section('Repository');
  const tracked = (git(dir, ['ls-files', '-z']) || '').split('\0').filter(Boolean);
  if (!tracked.length) { fail('git', `${dir} has a .git folder but git ls-files returned nothing (is git installed?)`); return; }
  info('tracked', `${tracked.length} tracked file(s) in ${dir}`);
  const branch = (git(dir, ['rev-parse', '--abbrev-ref', 'HEAD']) || '').trim();
  if (branch) info('branch', `current branch: ${branch}${branch === 'main' || branch === 'master' ? '' : ' — make sure the host builds production from main, not from this branch (guide PART 7)'}`);

  // files that must never be tracked
  const bad = tracked.filter((f) => /(^|\/)(\.env(\.[^/]*)?|\.dev\.vars|\.npmrc|\.netrc|\.pypirc|id_(?:rsa|ed25519|ecdsa)(?:\.pub)?|[^/]*\.pem|[^/]*\.p12|[^/]*\.pfx|[^/]*\.key|credentials(?:\.json)?|service-account[^/]*\.json|\.claude\/settings\.local\.json|\.claude\/[^/]*\.json|settings\.local\.json|\.vscode\/settings\.json|\.idea\/[^/]*|wrangler\.toml|\.wrangler\/.*|\.dev\.vars\.[^/]*)$/i.test(f));
  const benign = (f) => /\.example$|\.sample$|\.template$|\.pub$/i.test(f) || (/wrangler\.toml$/.test(f) && !/(secret|token|key)\s*=/i.test(readFileSync(join(dir, f), 'utf8')));
  const really = bad.filter((f) => !benign(f));
  if (really.length) fail('tracked-secrets', `credential / local-config files are tracked: ${really.slice(0, 8).join(', ')} — remove from the index, add to .gitignore, rotate what they held`);
  else pass('tracked-secrets', 'no .env / .dev.vars / key / local settings files tracked');
  const claudeDir = tracked.filter((f) => /^\.claude\//.test(f) && !/^\.claude\/(?:skills|commands|agents)\//.test(f) && !/CLAUDE\.md$/.test(f));
  if (claudeDir.length) warn('claude-dir', `.claude/ files tracked: ${claudeDir.slice(0, 4).join(', ')} — settings.local.json and anything with keys must stay out; skills/ and CLAUDE.md are fine`);

  // .gitignore coverage
  const gi = existsSync(join(dir, '.gitignore')) ? readFileSync(join(dir, '.gitignore'), 'utf8') : '';
  const want = [['.env', /^\s*\.env(\*|\.\*)?\s*$|^\s*\*?\.env\*/m], ['.dev.vars', /^\s*\.dev\.vars/m], ['node_modules', /^\s*\/?node_modules\/?\s*$/m], ['dist', /^\s*\/?dist\/?\s*$/m], ['local settings (*.local.json or the agent folder)', /settings\.local\.json|\*\.local\.json|\.local\.\*|^\s*\.(claude|cursor|windsurf)\/?\s*$/m]];
  const excl = existsSync(join(dir, '.git', 'info', 'exclude')) ? readFileSync(join(dir, '.git', 'info', 'exclude'), 'utf8') : '';
  // (for a public repo, consider ignoring the whole .claude/, .cursor/ etc. — see the AI footprint section)
  const missing = want.filter(([, re]) => !re.test(gi) && !re.test(excl)).map(([n]) => n);
  if (!gi) warn('gitignore', 'no .gitignore');
  else if (missing.length) warn('gitignore', `.gitignore does not cover: ${missing.join(', ')}`);
  else pass('gitignore', '.gitignore (or .git/info/exclude) covers .env*, .dev.vars, node_modules, dist, local settings');

  // secrets and security vocabulary in tracked text files
  section('Working tree');
  let secretHits = 0, vocabFiles = [], stagingFiles = [], emailFiles = [];
  const textish = tracked.filter((f) => /\.(md|mdx|txt|json|jsonc|ya?ml|toml|ts|tsx|js|mjs|cjs|astro|svelte|vue|html|css|env|sh|ps1|ini|cfg|conf|xml|svg)$/i.test(f) || /^[^.]*$/.test(f.split('/').pop()));
  for (const f of textish) {
    let s; try { s = readFileSync(join(dir, f), 'utf8'); } catch { continue; }
    if (s.length > 2 * 1024 * 1024 || /\u0000/.test(s.slice(0, 1000))) continue;
    if (/(^|\/)package-lock\.json$|(^|\/)pnpm-lock\.yaml$|(^|\/)yarn\.lock$/.test(f)) continue;
    const sec = findSecrets(s).filter((x) => !/^assignment/.test(x) || !/\.(md|example|sample)$/i.test(f));
    if (sec.length) { secretHits++; fail('secret', `${f}: credential-shaped string(s): ${sec.join(', ')} — rotate first, then remove and rewrite history`); }
    if (/\.(md|mdx|txt)$/i.test(f)) {
      const v = findSecurityVocab(s); if (v.length) vocabFiles.push(`${f} (${v.slice(0, 3).join(', ')})`);
      const h = findStagingHosts(s).filter((x) => !/^(localhost|127\.0\.0\.1)/.test(x)); if (h.length) stagingFiles.push(`${f} (${h[0]})`);
      const e = findEmails(s); if (e.length) emailFiles.push(`${f} (${e[0]})`);
    }
  }
  if (!secretHits) pass('secret', `${textish.length} text file(s): no credential-shaped strings`);
  if (vocabFiles.length) warn('docs-security', `docs describe the security setup: ${vocabFiles.slice(0, 5).join('; ')} — docs should say where it is configured, not how (policies, scopes, login method, app names)`);
  else pass('docs-security', 'docs do not describe the security setup');
  if (stagingFiles.length) warn('docs-staging', `docs name staging / preview hosts: ${stagingFiles.slice(0, 4).join('; ')}`);
  if (emailFiles.length) warn('docs-email', `docs contain account email addresses: ${emailFiles.slice(0, 4).join('; ')} — they tell a phisher which account to target`);
  const comments = [];
  for (const f of textish.filter((f) => /\.(ts|tsx|js|mjs|cjs|astro|svelte|vue)$/i.test(f))) {
    let s; try { s = readFileSync(join(dir, f), 'utf8'); } catch { continue; }
    if (s.length / (s.split('\n').length || 1) > 300) continue; // minified / vendored bundle, not hand-written comments
    for (const m of s.matchAll(/(?:\/\/|\/\*|<!--|#)\s*([^\n]*)/g)) {
      const c = m[1];
      if (/\\b|\(\?:|\[\^/.test(c)) continue; // regex source, not prose
      if (/\b(?:token|secret|api key|password|credential)\b/i.test(c) && /\b(?:prefix|starts with|begins with|format|looks like|scoped? to|permission|read\/write|expires?)\b/i.test(c)) { comments.push(`${f}: "${c.trim().slice(0, 70)}"`); if (comments.length > 6) break; }
    }
    if (comments.length > 6) break;
  }
  if (comments.length) warn('code-comments', `comments that describe credentials or their shape: ${comments.slice(0, 3).join(' | ')} — a comment like "token (prefix …), server-side" is a search hint`);
  else pass('code-comments', 'no comments describing credentials');

  // AI footprint in the repository
  section('AI footprint');
  const aiTracked = tracked.filter((f) => AI_FILE_RE.test(f));
  const aiDocs = [];
  for (const f of textish.filter((f) => /\.(md|mdx|txt|json|html)$/i.test(f) && !AI_FILE_RE.test(f))) { let s; try { s = readFileSync(join(dir, f), 'utf8'); } catch { continue; } const m = findAiFootprint(s); if (m) aiDocs.push(`${f} ("${m}")`); if (aiDocs.length >= 4) break; }
  const aiCommits = (git(dir, ['log', '--all', '-i', '-E', '--grep=co-authored-by: *(claude|copilot|chatgpt|gemini|cursor|codex|aider|devin)|generated with \\[?claude|🤖 generated|claude-session:|anthropic\\.com', '--format=%h'], { okStatus: [0, 1] }) || '').split('\n').filter(Boolean);
  const aiParts = [];
  if (aiTracked.length) aiParts.push(`config files: ${aiTracked.slice(0, 4).join(', ')}`);
  if (aiDocs.length) aiParts.push(`attribution in docs: ${aiDocs.slice(0, 2).join('; ')}`);
  if (aiCommits.length) aiParts.push(`${aiCommits.length} commit(s) with AI co-author / generator trailers`);
  if (aiParts.length) warn('ai-footprint', `the repository shows it was built with an AI assistant — ${aiParts.join('; ')}. For a public repo this is a targeting signal: keep agent config private (git-ignored or a separate private repo), drop the trailers, say nothing about the tooling (guide PART 7.6)`);
  else pass('ai-footprint', 'no AI-assistant config files, attribution or commit trailers');

  // one-off scripts that write into CMS-managed content folders (guide 6.7: the repo is the content's source of truth)
  section('CMS');
  const readSafe = (f) => { try { return readFileSync(join(dir, f), 'utf8'); } catch { return ''; } };
  const cmsCfg = tracked.find((f) => /(^|\/)config\.ya?ml$/.test(f) && /collections:/.test(readSafe(f)));
  if (cmsCfg) {
    const folders = [...new Set([...readSafe(cmsCfg).matchAll(/^\s*(?:folder|media_folder):\s*["']?([^"'\s#]+)/gm)].map((m) => m[1].replace(/^\/+|\/+$/g, '')))].filter(Boolean);
    const writers = [];
    for (const f of tracked.filter((f) => /\.(m?js|cjs|ts|py|sh)$/i.test(f) && !/(^|\/)(node_modules|dist|src\/pages|src\/components|src\/layouts)\//.test(f))) {
      const t = readSafe(f);
      if (!/writeFile|writeFileSync|open\([^)]*['"]w|>\s*\$?[A-Za-z_./]*\.md/.test(t)) continue;
      const hit = folders.find((fo) => t.includes(fo)); if (hit) writers.push(`${f} → ${hit}`);
    }
    if (writers.length) warn('cms-writers', `script(s) write into CMS-managed folders: ${writers.slice(0, 4).join('; ')} — once editors publish from the CMS, a re-run overwrites their work (guide 6.7); delete one-off importers or move them out of the repo`);
    else pass('cms-writers', `no script writes into the ${folders.length} CMS-managed folder(s) from ${cmsCfg}`);
  }

  // history
  if (opt.history) {
    section('History');
    const revs = (git(dir, ['rev-list', '--all', '--count']) || '0').trim();
    info('commits', `${revs} commit(s) across all refs`);
    const patterns = ['AKIA[0-9A-Z]{16}', 'BEGIN (RSA|EC|OPENSSH|DSA|PGP )?PRIVATE KEY', '\\bgh[pousr]_[A-Za-z0-9]{36,}', 'github_pat_[A-Za-z0-9_]{60,}', 'xox[abprs]-[A-Za-z0-9-]{10,}', '[sr]k_(live|test)_[A-Za-z0-9]{16,}', 'shp(at|ca|pa|ss)_[a-fA-F0-9]{32}', 'AIza[0-9A-Za-z_-]{35}', 'npm_[A-Za-z0-9]{36}', 'glpat-[A-Za-z0-9_-]{20,}'];
    const revList = (git(dir, ['rev-list', '--all', '--max-count=4000']) || '').split('\n').filter(Boolean);
    let out = '', failed = false;
    for (let i = 0; i < revList.length; i += 200) {
      const chunk = git(dir, ['grep', '-l', '-I', '-E', patterns.join('|'), ...revList.slice(i, i + 200)], { maxBuffer: 256 * 1024 * 1024, okStatus: [0, 1] });
      if (chunk === null) { failed = true; break; }
      out += chunk;
    }
    if (failed) info('history-scan', 'git grep over history failed (shallow clone or very large repo?) — run it by hand: git grep -lE <patterns> $(git rev-list --all)');
    else {
      if (revList.length >= 4000) info('history-scan', 'history scan capped at the 4000 most recent commits');
      const hits = [...new Set(out.split('\n').filter(Boolean).map((l) => l.replace(/^[0-9a-f]{7,40}:/, '')))];
      if (hits.length) fail('history-secret', `credential-shaped strings in git history (${hits.length} file path(s), e.g. ${hits.slice(0, 3).join(', ')}) — rotate, then rewrite history with git filter-repo and ask GitHub Support to purge PR refs (guide PART 7)`);
      else pass('history-secret', 'no credential-shaped strings anywhere in history');
    }
    const envHist = git(dir, ['log', '--all', '--diff-filter=A', '--name-only', '--format=', '--', '.env', '.env.*', '**/.env', '**/.env.*', '.dev.vars', '**/.dev.vars']);
    const envFiles = [...new Set((envHist || '').split('\n').filter(Boolean))].filter((f) => !/\.(example|sample|template)$/i.test(f));
    if (envFiles.length) fail('history-env', `env files were committed at some point: ${envFiles.slice(0, 4).join(', ')} — they are still in history; rotate and rewrite`);
    else pass('history-env', 'no .env / .dev.vars ever committed');
    const esc = (w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (opt.forbid.length) {
      const details = [];
      for (const w of opt.forbid) {
        const paths = (git(dir, ['grep', '-l', '-i', '-I', '-E', `(^|[^a-zA-Z0-9])${esc(w)}([^a-zA-Z0-9]|$)`, ...revList.slice(0, 200)], { okStatus: [0, 1] }) || '').split('\n').filter(Boolean);
        if (!paths.length) continue;
        const files = [...new Set(paths.map((l) => l.replace(/^[0-9a-f]{7,40}:/, '')))];
        const last = (git(dir, ['log', '--all', '-1', '--format=%h %ad', '--date=short', '-i', `-S${w}`]) || '').trim();
        details.push(`"${w}": ${files.length} file(s) e.g. ${files[0]}${last ? `, last touched ${last}` : ''}`);
      }
      if (details.length) warn('history-forbid', `forbidden strings in history — ${details.join('; ')}. Still in HEAD? fix the file. Only in history? decide whether a rewrite is worth it.`); else pass('history-forbid', 'forbidden strings never appear in history');
    }
  }
  const remote = (git(dir, ['remote', 'get-url', 'origin']) || '').trim();
  if (remote) { section('Repository'); info('remote', `origin: ${remote.replace(/\/\/[^@]+@/, '//***@')}${/github\.com/.test(remote) ? ' — if the site has a CMS or drafts, this repo must be private; check forks = 0 before any history rewrite' : ''}`); }
}

// ───────────────────────────── init ─────────────────────────────
async function initProject(dir) {
  const { writeFileSync, mkdirSync, appendFileSync } = await import('node:fs');
  const here = new URL('.', import.meta.url);
  const tpl = (name) => readFileSync(new URL(`../templates/${name}`, here), 'utf8');
  const rules = readFileSync(new URL('../reference/build-rules.md', here), 'utf8');
  const written = [], skipped = [];
  const put = (relPath, content) => {
    const abs = join(dir, relPath);
    if (existsSync(abs) && !opt.force) { skipped.push(relPath); return; }
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, content); written.push(relPath);
  };
  let post = tpl('kekkai-postbuild.mjs');
  if (opt.admin) post = post.replace("const ADMIN = process.env.KEKKAI_ADMIN || '';", `const ADMIN = process.env.KEKKAI_ADMIN || '${opt.admin}';`);
  put('scripts/kekkai-postbuild.mjs', post);
  put('kekkai-rules.md', rules);
  // .gitignore block (append, idempotent)
  const gi = join(dir, '.gitignore'); const block = `
# kekkai: local and agent files never tracked
.env
.env.*
!.env.example
.dev.vars
*.local.json
.claude/
CLAUDE.md
CLAUDE.local.md
AGENTS.md
.cursor/
.cursorrules
node_modules/
dist/
.astro/
.DS_Store
Thumbs.db
`;
  const giNow = existsSync(gi) ? readFileSync(gi, 'utf8') : '';
  if (!/# kekkai:/.test(giNow)) { appendFileSync(gi, block); written.push('.gitignore (block appended)'); } else skipped.push('.gitignore (block present)');
  // package.json build script, only when it is exactly "astro build"
  const pj = join(dir, 'package.json'); let buildNote = '';
  if (existsSync(pj)) {
    const pkg = JSON.parse(readFileSync(pj, 'utf8'));
    if (pkg.scripts?.build === 'astro build') { pkg.scripts.build = 'astro build && node scripts/kekkai-postbuild.mjs'; writeFileSync(pj, JSON.stringify(pkg, null, 2) + '\n'); written.push('package.json ("build" now runs the post-build script)'); }
    else buildNote = `  package.json: make "build" end with  && node scripts/kekkai-postbuild.mjs   (current: ${JSON.stringify(pkg.scripts?.build || '')})`;
  }
  if (existsSync(join(dir, 'public', '_headers'))) buildNote += (buildNote ? '\n' : '') + '  public/_headers exists — delete it; the post-build script generates dist/_headers now.';
  console.log(`\nkekkai init — ${dir}\n`);
  for (const w of written) console.log(`  + ${w}`);
  for (const k of skipped) console.log(`  = ${k} (exists; --force to overwrite)`);
  console.log(`
  Next:
  1. astro.config.mjs:
       build: { inlineStylesheets: 'never' },
       vite: { build: { assetsInlineLimit: 0 } },
       markdown: { syntaxHighlight: false },   // or a class-based highlighter
  2. Edit the CONFIG block at the top of scripts/kekkai-postbuild.mjs (media/embed hosts, CMS folder${opt.admin ? ` — set to "${opt.admin}"` : ', or KEKKAI_ADMIN env'}).
${buildNote ? buildNote + '\n' : ''}  3. Give kekkai-rules.md to whoever writes the code (you or your assistant) before the first component.
  4. Before every release: kekkai . --forbid … ; npm run build ; kekkai ./dist${opt.admin ? ` --admin ${opt.admin}` : ''} ; deploy ; kekkai https://<site>${opt.admin ? ` --admin ${opt.admin}` : ''} --accept-edge-inline
`);
}

// ───────────────────────────── run ─────────────────────────────
const isDir = !/^https?:\/\//i.test(target) && existsSync(target) && statSync(target).isDirectory();
if (opt.init) { await initProject(target || '.'); process.exit(0); }
const isRepo = isDir && (opt.mode === 'repo' || (opt.mode !== 'dist' && existsSync(join(target, '.git')) && !existsSync(join(target, '_headers')) && !existsSync(join(target, 'index.html'))));
if (isRepo) repoScan(target); else if (isDir) distScan(target); else await liveScan(target);

const counts = { pass: 0, warn: 0, fail: 0, info: 0 };
for (const r of results) counts[r.level]++;
const failed = counts.fail > 0 || (opt.strict && counts.warn > 0);
const mode = isRepo ? 'repository' : isDir ? 'build output' : 'live';
const again = isRepo ? 'then scan the build and the live site' : 'then run again against the LIVE response';
const isLive = !isDir;
const handoff = isLive ? `senrigan (千里眼) reads the other half of the same boundary — what the site fails to tell search engines and LLMs. Same target:\n    npx github:kappa-yashi/senrigan ${target}` : isRepo ? '' : `senrigan (千里眼) reads the other half of the same boundary — titles, canonicals, sitemap, structured data. Same folder:\n    npx github:kappa-yashi/senrigan ${target}`;
const verdict = failed ? `BOUNDARY BROKEN — fix the ✖ items, ${again}.` : isRepo ? 'BOUNDARY HOLDS — repository clean. Next: scan dist/ and the live site.' : 'BOUNDARY HOLDS — no failures. Re-run after deploy: the live response is the only truth.';
const plainMark = { pass: '✔', warn: '!', fail: '✖', info: '·' };
function render(fmt, color) {
  const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const mark = { pass: c(32, '✔'), warn: c(33, '!'), fail: c(31, '✖'), info: c(90, '·') };
  const shown = opt.summary ? results.filter((r) => r.level === 'fail' || r.level === 'warn') : results;
  const lines = [];
  if (fmt === 'md') {
    lines.push(`# kekkai (結界) — ${mode} scan of ${target}`, '', `**${counts.pass} pass · ${counts.warn} warn · ${counts.fail} fail · ${counts.info} info** — ${verdict}`, '');
    let last = ''; for (const r of shown) { if (r.section !== last) { lines.push('', `## ${r.section}`, ''); last = r.section; } lines.push(`- ${plainMark[r.level]} ${r.msg}${r.detail && r.level !== 'pass' ? `\n  \`${String(r.detail).replace(/\n/g, ' ')}\`` : ''}`); }
    if (handoff) lines.push('', '## Hand-off', '', handoff.replace(/\n    /, '\n\n```\n') + '\n```');
    return lines.join('\n') + '\n';
  }
  lines.push('', `kekkai (結界) — ${mode} scan of ${target}`, '');
  let last = '';
  for (const r of shown) {
    if (!opt.summary && r.section !== last) { lines.push(c(1, `  ${r.section}`)); last = r.section; }
    lines.push(`    ${mark[r.level]} ${opt.summary ? `[${r.section}] ` : ''}${r.msg}`);
    if (!opt.summary && r.detail && r.level !== 'pass') for (const l of String(r.detail).split('\n')) lines.push(c(90, `        ${l}`));
  }
  lines.push('', `  ${c(32, counts.pass + ' pass')}  ${c(33, counts.warn + ' warn')}  ${c(31, counts.fail + ' fail')}  ${c(90, counts.info + ' info')}`, '', `  ${c(failed ? 31 : 32, verdict)}`);
  if (handoff) lines.push('', c(90, `  Hand-off · ${handoff.split('\n')[0]}`), c(90, `  ${handoff.split('\n')[1].trim()}`));
  lines.push('');
  return lines.join('\n');
}
const jsonOut = () => JSON.stringify({ target, mode: isRepo ? 'repo' : isDir ? 'dist' : 'live', counts, ok: !failed, senrigan: handoff ? `npx github:kappa-yashi/senrigan ${target}` : null, results }, null, 2);
if (opt.json) console.log(jsonOut()); else console.log(render('text', process.stdout.isTTY));
if (opt.out) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync(opt.out, opt.out.endsWith('.json') ? jsonOut() : opt.out.endsWith('.md') ? render('md', false) : render('text', false));
  console.error(`report written to ${opt.out}`);
}
process.exit(failed ? 1 : 0);
