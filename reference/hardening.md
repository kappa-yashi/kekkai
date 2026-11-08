# Hardening a static site on an edge host

> Part of [kekkai (結界)](https://github.com/kappa-yashi/kekkai) by kappa.yashi.
> This guide is licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/):
> reuse and adapt it freely, credit kappa.yashi and link to the source.
> The scanner that goes with it is MIT.

The reference stack is Astro, built to static files, served by Cloudflare
Pages. Almost all of it transfers to Netlify or any host that applies a
`_headers` file at the edge. Everything here was learned from shipping real
sites; every trap is recorded because it cost real time.

## The governing principle

Two questions, opposite answers. Keep them apart and most decisions resolve
themselves.

- **What the site does** (content, semantics, identity, schema, llms.txt):
  wide open. You want search engines, AI assistants and humans to read and cite
  it.
- **How the site is built** (endpoints, repositories, stack, versions, admin
  surfaces, hosting internals): invisible. It is nobody's business and every
  disclosure is free reconnaissance.

A static build with no database, no server-side application, no accounts and
no admin interface is not a limitation. It is the security property. Say so in
the privacy policy, and do not trade it away to make a vendor's "agent
readiness" score go up. Those scores reward publishing an API, an OpenAPI
spec, OAuth endpoints and an agent manifest. For a portfolio, brochure, blog
or zine that is pure added attack surface, and a zero is the correct result.

## Order of work

1. Pick the CSP strategy (start of PART 2). It decides how PART 1 is written.
2. `_headers`, static or generated (PART 1)
3. CSP (PART 2)
4. Deploy fingerprint (PART 3)
5. Host dashboard audit (PART 4)
6. Build-output leak audit + automated tests (PART 5)
7. CMS surface, if there is one (PART 6)
8. Repository and docs hygiene: what the repo itself discloses (PART 7)
9. Verify every item against the live response, not against intent

---

# PART 1: _headers

Pages applies `_headers` from the build output at the edge. Rules are
**additive**: a `/*` block applies to every path, and more specific blocks add
to it rather than replacing it. Pages consumes `_headers`; it is not served as
a page.

```
# The build fingerprint: no-store, because its whole job is to be the one thing
# no cache, proxy or link-preview scraper can answer out of date.
/version.txt
  Cache-Control: no-store

/fonts/*
  Cache-Control: public, max-age=31536000, immutable

/_astro/*
  Cache-Control: public, max-age=31536000, immutable

/*
  # Force HTTPS for a year. See Trap 1.5 on "preload".
  Strict-Transport-Security: max-age=31536000; includeSubDomains

  # Strategy A: frame-ancestors is IGNORED inside a meta tag, so it must be a
  # real header; the rest of the CSP is a per-page meta tag (PART 2).
  # Strategy B: delete this line, the full CSP goes on document paths (Trap 1.3).
  Content-Security-Policy: frame-ancestors 'none'
  X-Frame-Options: DENY

  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin

  Permissions-Policy: accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), interest-cohort=()

  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin

  X-DNS-Prefetch-Control: off

  # See Trap 1.1. Remove the wildcard, then VERIFY it is gone live.
  # If it survives on your project, set a narrow value instead:
  #   Access-Control-Allow-Origin: https://www.example.com
  #   Vary: Origin
  ! Access-Control-Allow-Origin
```

`Referrer-Policy: no-referrer` is a valid stricter choice for a site that links
out a lot and has no analytics depending on referrers. Outbound clicks then
tell the destination nothing about where the reader came from.

## Generate _headers at build when the CSP depends on data

If the CSP has to name a host that lives in a data file (a media bucket, an
embed provider configured by an editor), a hand-written `public/_headers` will
drift the first time the host changes. Write `_headers` from a tiny Astro
integration instead:

```js
// astro.config.mjs
import { writeFileSync } from 'node:fs';
import { headersFile } from './src/config/headers.ts';
const headers = () => ({
  name: 'site-headers',
  hooks: { 'astro:build:done': ({ dir }) => writeFileSync(new URL('_headers', dir), headersFile()) },
});
export default defineConfig({ integrations: [headers()] /* … */ });
```

```ts
// src/config/headers.ts  (shape only; adapt the lists)
import media from '../data/media.json';
const mediaHost = (() => { try { return new URL(media.baseUrl).origin; } catch { return ''; } })();
const DOC_CSP = [ /* see PART 2, Strategy B */ `media-src 'self'${mediaHost ? ' ' + mediaHost : ''}` ].join('; ');
const DOC_PATHS = ['/', '/posts/*', '/tags/*', '/about/*', '/404.html' /* every HTML route */];
export function headersFile() { /* emit /*, cache blocks, then one CSP block per DOC_PATH, then the CMS block */ }
```

Do **not** also keep a `public/_headers`: two sources of truth, and one of them
overwrites the other. Make the build **fail** if `public/_headers` reappears.

**Better still: derive the document path list from the build output.** A
post-build script that walks `dist/**/*.html`, emits one CSP block per route
(or per route group) and writes `_headers` closes two traps at once: no CSP
under `/*` (Trap 1.3), and no new page can ship without a CSP, because the list
is the output itself. The same script is the natural place to stamp
`version.txt` (PART 3) from `CF_PAGES_COMMIT_SHA`, and to strip comments from
any config file that is served publicly (a CMS `config.yml`), since those
comments are read by everyone. `kekkai init` scaffolds exactly this script
(`scripts/kekkai-postbuild.mjs`), and `reference/build-rules.md` is the
DO/DON'T list to write the site by so that nothing is left for the scan.

## Trap 1.1: the Access-Control-Allow-Origin wildcard

Cloudflare Pages can add `Access-Control-Allow-Origin: *` to responses on its
own. That tells every browser that any other site's JavaScript may read these
responses. Nothing on a static site needs that.

The Pages removal syntax is `! Access-Control-Allow-Origin`. It is honoured on
some projects and not on others (the platform may add the header after
`_headers` is applied). So write the removal, then **read the live headers**.
If the wildcard survives, **set** a narrow value instead
(`Access-Control-Allow-Origin: https://www.example.com` + `Vary: Origin`). A
set overrides a platform default, and your own origin grants nothing to anyone
else. The header takes **one** origin, not a list.

**Fonts: a same-origin font does NOT need this header.** Astro font preloads
carry `crossorigin`, so the browser fetches the font in CORS mode, but for a
**same-origin** URL it runs no CORS check and the response is used as is. ACAO
only matters for fonts fetched **across origins**: a page on `www` loading
fonts from the apex, fonts on a separate CDN or assets subdomain, a preview
host loading fonts from the custom domain. In those cases set the font host's
ACAO to the page's origin, on the font path only. If fonts fall back after a
header change, check DevTools -> Network -> the font request first.

## Trap 1.2: _redirects cannot match hostnames

The Pages `_redirects` file matches **paths only**. An apex-to-www redirect is
a **Redirect Rule in the Cloudflare dashboard**, scoped to the zone. When you
write it, match `http.host **equals** apex.example.com`. If it says `contains`,
it matches `www.example.com` too, sends the page to itself, and every crawler
reports a redirect loop. A Redirect Rule also cannot touch `*.pages.dev`: that
is Cloudflare's zone, not yours. See PART 4.

## Trap 1.3: two CSP headers on one path are BOTH enforced

Because `_headers` rules are additive, a CSP under `/*` plus a different CSP
under `/cms/*` sends **two** `Content-Security-Policy` headers to the CMS page.
Browsers enforce every policy they receive, so the effective policy is the
intersection. The CMS's wider policy can only narrow, never widen, and the
admin breaks.

So with header CSPs, **never put a CSP under `/*`**. Attach the document CSP to
an explicit list of document paths, and give the CMS path its own block. The
cost is that a new top-level route ships **without** a CSP unless you add it to
the list. Make the build check it (PART 5).

## Trap 1.4: different content, different CSP

Not every path needs the same policy. Typical split:

- documents: the strict site policy (PART 2, Strategy B)
- a plain-text or feed route that needs nothing: `default-src 'none';
  style-src 'none'; script-src 'none'; img-src 'none'; frame-ancestors 'none';
  base-uri 'none'; form-action 'none'`
- the CMS: its own wider policy, `no-store`, `X-Robots-Tag: noindex` (PART 6)

## Trap 1.5: HSTS preload is a one-way door

`max-age=63072000; includeSubDomains; preload` is a defensible choice, and so
is leaving `preload` off. The rule is to decide on purpose: once a domain is in
the browsers' preload lists, every subdomain must serve HTTPS for years, and
removal is slow. Do not copy the line between projects without making that
decision for the new domain.

## Verifying headers

Check the **status code, not the body**. An HTTP client that follows redirects
silently will report the apex as serving the page directly, which is wrong.

Check **two** request types in DevTools -> Network -> Response Headers: an HTML
document **and** a font or CSS file. Hosts can treat assets differently from
documents, and the asset is where CORS actually matters.

**Tick "Disable cache" first.** A response marked "(from disk cache)" shows the
headers it had **when it was cached**, which can be days old. With immutable
assets that cache lives for a year. Read headers only from a fresh request,
and check the `Date` header to be sure.

---

# PART 2: Content Security Policy

## Choose a strategy first

| | Strategy A: per-page meta + hashes | Strategy B: zero inline, header CSP |
|---|---|---|
| Where | `<meta>` per page + `frame-ancestors` header | `_headers`, one policy per path group |
| `script-src` | `'self'` + sha384 of each inline script | `'self'` only |
| `style-src` | `'self' 'unsafe-inline'` (usually) | `'self'` only |
| Build step | post-build hashing script | none (just never emit inline code) |
| Script injected through content | gets hashed and **allowed** (6.5) | **blocked**, no extra work |
| Fits | existing site with `?raw` inlined scripts, inline `style=` | codebase you control end to end |

Prefer **B** when you write the code. It is simpler (no post-build rewriting),
stricter on both scripts and styles, and a hash-based CSP blesses whatever ends
up in the HTML, including what an editor typed. Use **A** when retrofitting a
site whose components depend on inline scripts or inline styles.

## Strategy B: zero inline

The policy, on every document path:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; media-src 'self' https://media.example.com;
manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none';
frame-src https://the-one-embed.example; frame-ancestors 'none'; upgrade-insecure-requests
```

Start from `default-src 'none'` and add only what a real feature needs. Each
exception is scoped to one directive and one origin (one embed provider, one
media host). `form-action 'none'` and `base-uri 'none'` cost nothing on a site
without forms.

What it takes in Astro:

```js
// astro.config.mjs
export default defineConfig({
  build: { inlineStylesheets: 'never' },        // CSS as files, never <style>
  vite: { build: { assetsInlineLimit: 0 } },    // no small script/asset inlined into the HTML
  markdown: { syntaxHighlight: false },         // Shiki emits style="" on every token
});
```

- **Scripts.** Every `<script>` in components is processed and bundled by
  Astro into `/_astro/*.js`. With `assetsInlineLimit: 0` none of them gets
  inlined. The only allowed inline `<script>` is `type="application/ld+json"`,
  which is never executed and needs no permission.
- **Code that must run before first paint** (theme restore, no flash) is a
  small **external** file in `public/`, loaded with
  `<script is:inline src="/theme-init.js?v={hash}">` at the top of `<head>`.
  Blocking, external, CSP-clean. `?v=` is a content hash computed at build.
- **Validate everything that file reads from storage before applying it.**
  `localStorage` is attacker-writable from any XSS or from a shared machine.
  Accept a theme id only if it matches `/^[a-z0-9-]+$/`, a colour only if it
  matches `/^#[0-9a-f]{6}$/i`, an enum only from its list.
- **No `style=""` anywhere.** Dynamic values go through **data attributes**
  and CSS, or through the **CSSOM** from JS (`el.style.setProperty('--x', v)`).
  `style-src` governs `style=""` attributes and `<style>` elements; it does not
  govern CSSOM writes from an allowed script.
- **Editor-controlled colours** (per-category colours, themes) are generated
  into a CSS endpoint at build (`src/pages/palette.css.ts`) as classes, linked
  with `?v=<hash>` for cache busting. Never render them as inline styles.
- **Syntax highlighting:** off, or a highlighter that emits classes.
- **A client-side router** that swaps `<body>` on navigation never executes
  inline scripts in the new body anyway. Keep all behaviour in bundled modules
  with event delegation and an `initPage()` hook the router calls.

## Strategy A: per-page meta with script hashes

### Why a post-build script and not Astro's built-in CSP

Astro's experimental CSP does not cover scripts injected with
`<script is:inline set:html={...}>`. If the site imports scripts with `?raw`
and inlines them that way, the built-in support will not hash them and the CSP
will block them. So the CSP is written **after** the build, per page, by a
script that hashes the actual inline scripts in the actual output.

### Why a meta tag per page, with one real header alongside

Each page has a different set of inline scripts, so each page needs a different
hash list. A single header for the whole site would have to be the union of all
hashes, which hands every page permission to run every other page's scripts.
But `frame-ancestors` is **ignored inside a meta tag**. Hence the split:
`frame-ancestors 'none'` lives in `_headers`, everything else is a per-page
meta tag.

### Reference implementation

```js
// scripts/csp.mjs  — run after `astro build`
//   "build": "astro build && node scripts/csp.mjs && node scripts/stamp.mjs"
import { readFileSync, writeFileSync, globSync } from 'node:fs';
import { createHash } from 'node:crypto';

const DIST = new URL('../dist/', import.meta.url);
const BASE = [
  "default-src 'self'", "img-src 'self' data:", "font-src 'self'", "connect-src 'self'",
  "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-src 'none'",
];
const sha384 = (s) => "'sha384-" + createHash('sha384').update(s, 'utf8').digest('base64') + "'";

for (const file of globSync('**/*.html', { cwd: DIST })) {
  const path = new URL(file, DIST);
  let html = readFileSync(path, 'utf8');
  const hashes = [];
  for (const [, attrs, body] of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
    if (/\ssrc=/.test(attrs)) continue;
    const type = (attrs.match(/type="([^"]*)"/)?.[1] || '').toLowerCase();
    if (type && !['text/javascript', 'application/javascript', 'module'].includes(type)) continue;
    hashes.push(sha384(body));
  }
  const policy = [...BASE, `script-src 'self' ${hashes.join(' ')}`.trim(), "style-src 'self' 'unsafe-inline'"].join('; ');
  // Must be the first thing in <head> the parser reaches, before any script it governs.
  html = html.replace(/<head>/i, `<head><meta http-equiv="content-security-policy" content="${policy}">`);
  writeFileSync(path, html);
}
```

### Trap 2.1: `style-src 'unsafe-inline'`

Under Strategy A, Astro's inlined stylesheets and components' inline `style=`
attributes usually force `'unsafe-inline'` for styles. It is a real weakening
but a much smaller one than for scripts: CSS injection without script execution
is mostly defacement. Do **not** copy the same permissiveness to `script-src`.

### Trap 2.2: anything that changes an inline script changes its hash

A one-character edit to an inline script invalidates its hash. The CSP must be
regenerated on **every** build, which is why it belongs in the build chain and
not in a manual step. If scripts stop running after a deploy, check this first.
`kekkai ./dist` recomputes every hash and tells you.

## Test locally with the real headers (both strategies)

`python3 -m http.server` and `astro preview` do **not** apply `_headers`. Under
Strategy B that means every CSP violation is invisible locally and shows up for
the first time in production. Serve `dist/` with a tiny server that reads
`dist/_headers` and applies it; then any browser run doubles as a CSP test, and
`kekkai http://127.0.0.1:4399` checks the same thing without a browser.

```python
# serve.py: static server on :4399 that applies dist/_headers
import http.server, socketserver, re
ROOT = 'dist'; rules = []
for line in open(ROOT + '/_headers'):
    if line.startswith('#') or not line.strip(): continue
    if not line.startswith(' '): rules.append((line.strip(), [])); continue
    k, _, v = line.strip().partition(': ')
    if not k.startswith('!'): rules[-1][1].append((k, v))
def match(p, pat):
    rx = '^' + re.escape(pat).replace(r'\*', '.*') + '$'
    return re.match(rx, p) or (p.endswith('/') and re.match(rx, p + 'index.html'))
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory=ROOT, **k)
    def end_headers(s):
        p = s.path.split('?')[0]
        for pat, hs in rules:
            if match(p, pat):
                for k, v in hs: s.send_header(k, v)
        super().end_headers()
    def log_message(s, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('127.0.0.1', 4399), H).serve_forever()
```

---

# PART 3: the deploy fingerprint

**Build this first, before anything else, and never skip it.**

Most builds of a site differ only in bytes nobody can see: a JSON-LD field, a
meta tag, a header. Two completely different versions can look identical in a
browser. So "does the site look right" can never answer "is the new build
deployed", and on edge hosts that question comes up constantly: cached link
previews, stale CDN copies and a deploy that landed on a non-production slot
all answer it differently.

One file ends it:

```js
// src/version.js  — bump BUILD before every package
export const BUILD = 'v1';
export const BUILT = '2026-01-01';
```

```js
// scripts/stamp.mjs  — runs after the build
import { writeFileSync } from 'node:fs';
import { BUILD, BUILT } from '../src/version.js';
writeFileSync(new URL('../dist/version.txt', import.meta.url), `${BUILD}\nbuilt ${BUILT}\n`);
```

In the base layout, so view-source carries the same answer:

```astro
<meta name="build" content={BUILD + ' ' + BUILT} />
```

Repeat that import by hand in any page that does **not** use the base layout
(typically `404.astro`).

`version.txt` is served `no-store` (PART 1), so no cache, proxy or scraper can
answer it out of date.

**Git-connected projects:** the host runs the build, so stamp the commit
automatically. Pages exposes it as an environment variable
(`CF_PAGES_COMMIT_SHA`; check the current docs for the exact name). Write it
into `version.txt` next to the human version from `package.json`.

If the live fingerprint disagrees with what you just shipped, the problem is on
the host side, not in the package: open the project's deployments and confirm
the newest one is the one marked **Production**. A direct upload can land on a
non-production deployment, report success, and leave the live site untouched.
A Git build can fail after the push, and the old deployment then stays live.

---

# PART 4: what the host dashboard does behind your back

Platform behaviours that no file in the repository can see or override. Audit
them, and re-audit after any dashboard change. The scanner can only observe
their effects.

## 4.1 A managed robots.txt can be prepended above yours

Cloudflare can inject its own block **above** the `robots.txt` you ship, and
nothing in the repo overrides it. If `Content-Signal` or `Disallow` lines ever
appear on the live file, the fix is Security -> Settings -> "Manage your
robots.txt" -> disable. Verify by fetching the live file and confirming nothing
sits above your own lines.

## 4.2 AI crawler categories

Cloudflare splits AI traffic into **Search**, **Agent** and **Training**, each
separately allowed or blocked. For newly onboarded zones, Training and Agent
may be blocked by default while Search stays allowed.

`robots.txt` is a **request**; the host's bot rules are **enforcement**, and
enforcement wins. A site whose robots.txt welcomes AI assistants while the host
blocks the Agent category is lying in public, is invisible to assistants
browsing live, and still looks fine in Google. Decide the three deliberately
and make `robots.txt` match. Security -> Events shows what was actually
challenged or blocked; everything else is inference.

## 4.3 Every deployment keeps a permanent public URL

A Pages project serves the whole site on `*.pages.dev` as well as on the custom
domain, and **every deployment ever made keeps its own permanent public preview
URL**. The entire history of half-finished and broken builds is reachable by
anyone who finds the address.

Closing it takes two separate steps, and the first one alone is not enough:

1. Pages project -> Settings -> **Preview access**. Covers preview URLs only.
2. The production hostname, added **by hand** as a second destination on the
   Access application that step 1 created:

   ```
   *.project.pages.dev     (previews, the whole history)
   project.pages.dev       (the live copy)
   ```

   A wildcard subdomain does **not** match the bare domain.

**The regeneration trap:** that Access application is *owned* by the Preview
access toggle. Turning the toggle off and on can regenerate the application and
silently drop the hand-added production destination. After any change to
Pages or Access settings, open the application and count the destinations.

Check the policy too. "All authenticated users" is not a lock; it admits anyone
who can authenticate with any configured provider. Use an **Emails** rule with
One-time PIN so you cannot lock yourself out.

**Never put the custom domain in that application's destinations.** That puts
the public site behind a login. (A separate Access application on **one path**
of the custom domain, such as the CMS, is different and fine; see 6.4.)

The SEO half needs nothing if every page carries an **absolute**
`<link rel="canonical">` to the custom domain: a crawled pages.dev copy then
points at the original and cannot compete with it.

## 4.4 Email obfuscation has two blind spots

Cloudflare's Email Address Obfuscation rewrites addresses in HTML, but only
while DNS is proxied, and it cannot reach:

- anything inside a `<script>` tag, which includes **JSON-LD**
- any **non-HTML file**: `llms.txt`, `sitemap.xml`, RSS feeds, plain-text
  mirrors

Those are exactly where a generator will happily put a contact address. Keep
addresses out of structured data and out of text files; point them at a
contact page instead. Obfuscation also makes mail links JavaScript-dependent,
which belongs in the accessibility statement.

For an address that has been harvested already, the only durable fix is to
stop publishing it: a label in the visible text, the address only in the
`mailto:` href, and no dictionary-attack local parts (`info@`, `contact@`,
`admin@`, `sales@`, `support@`, `hello@`).

Cloudflare's own paths (`/cdn-cgi/scripts/…`, the obfuscation decoder) are
served by Cloudflare, **not** from your `_headers`, so they carry none of your
headers. If HSTS matters there, turn it on at the zone (SSL/TLS -> Edge
Certificates -> HSTS); its `includeSubDomains` then covers every subdomain in
the DNS, so look at the DNS first.

## 4.5 The edge injects scripts your CSP never approved

Several Cloudflare features rewrite the HTML on the way out and add an
**inline `<script>`**: Bot Fight Mode's *JavaScript Detections*
(`window.__CF$cv$params` + `/cdn-cgi/challenge-platform/…`), Web Analytics
with automatic setup, Rocket Loader. Under `script-src 'self'` the browser
blocks it, every visitor gets a CSP error in the console, and the feature does
nothing. Nothing in the repository shows this; only the live response does, and
`dist/` scans pass. `kekkai <url>` reports it as an edge-injected inline script.

The script carries a per-request value, so it cannot be hashed; allowing it
needs a per-response nonce, which a static `_headers` file cannot provide. For
a static site the right answer is to **turn the feature off** (Security ->
Settings -> JavaScript detections; Web Analytics -> add the beacon yourself or
not at all; Speed -> Rocket Loader off) and check Security -> Events afterwards
that nothing you wanted blocked has stopped being blocked.

## 4.6 Production builds come from `main`, and only from `main`

Whatever goes online passes through a merge into `main` that a human does by
hand. This is not a security hole in the strict sense; it is **control**: the
merge forces you to look at what changes before it is public. If you cannot
see what ships, one day something ships that should not have.

- In the host's build settings the **production branch is `main`**; builds
  for other branches are off (or produce previews only).
- **Trap:** the production branch can be left pointing at a working branch
  (an agent session's branch, say, whose name changes every session). Then
  every push there goes live **with no PR and no review**, and when the next
  session uses a new branch name, deploys silently stop.
- **How it shows:** something is live that was never merged, or the
  Deployments list names a branch other than `main`.
- **Fix in this order:** (1) PR + merge the working branch into `main`, so
  `main` has what is already live, otherwise the switch rolls the site back;
  (2) change the production branch to `main`; (3) the setting change starts
  no build, the next push to `main` does; (4) verify the newest deployment
  says `main` and that a push to the working branch starts nothing.
- After every merge, one glance at Deployments: branch `main`.
- End-to-end tests run **before** the merge, because the merge is the deploy.

## 4.7 Account-wide toggles are not what you want

When a setting says "apply one account-wide policy across your Workers", two
words should send you elsewhere: **account-wide** and **Workers**. For one
hostname, create a single Access application scoped to exactly that hostname.

---

# PART 5: build-output leak audit

`kekkai ./dist` runs most of this automatically. The manual version, for
when you want to look with your own eyes:

```bash
ADMIN=your-cms-folder   # the CMS folder name, if any (PART 6)
echo "=== source maps ===";            find dist -name "*.map" | head
echo "=== repo / forge references ==="; grep -rohI "[^ \"']*\(github\.com\|gitlab\|bitbucket\)[^ \"'<)]*" dist/ --exclude-dir="$ADMIN" --exclude=_headers | sort -u
echo "=== strings that must never appear ==="
for t in internal-codename staging-hostname client-name; do
  printf "  %-20s %s file(s)\n" "$t" "$(grep -ril "$t" dist/ 2>/dev/null | wc -l)"
done
echo "=== build/config files that should not ship ==="
find dist \( -name "package*.json" -o -name "*.lock" -o -name ".env*" -o -name "*.config.*" -o -name ".git" \) | head
echo "=== stack disclosure ===";          grep -ro 'name="generator"[^>]*' dist/ | head
echo "=== local filesystem paths ===";    grep -rohI "/home/[a-z]*/[a-zA-Z0-9_/.-]*" dist/ | sort -u | head -5
echo "=== CMS path outside its own folder (only _headers may name it) ==="
[ -n "$ADMIN" ] && grep -rlI "$ADMIN" dist/ | grep -v "^dist/$ADMIN/" | grep -v '^dist/_headers$'
echo "=== executable inline scripts (Strategy B: expect none) ==="
grep -rhoI '<script[^>]*>' dist --include=*.html | grep -v 'src=' | grep -v 'application/ld+json' | sort | uniq -c
echo "=== inline style attributes (Strategy B: expect none) ==="
grep -rlI '<[a-z][^>]* style="' dist --include=*.html --exclude-dir="$ADMIN" | head
echo "=== everything actually served ==="; find dist -type f | sed 's|dist/||' | sort
```

A repository URL in the output is not automatically a leak. An MIT attribution
for a ported component is required by its licence. A download link to a
**public** release repository is content, not reconnaissance. Read what each
match is before removing it. But note what a public sibling repository does
disclose: the **organisation name**. If the site's own repository lives under
the same organisation, it must be private (6.3), because its name is now one
guess away.

The forbidden-strings check (`--forbid`) is for internal codenames, staging
hostnames, client names that have not been announced, and anything else that
must not be publicly linked to the site. It is cheap and it is the kind of
thing a single stray comment gives away forever.

## Every HTML file must be covered by a CSP rule

Under Strategy B a new route added to `src/pages/` without being added to the
CSP path list ships with no CSP and nothing complains. `kekkai ./dist`
reports it; wire the same check into the build so it cannot be forgotten.

## Automated tests worth keeping in the repo

They need a built site being served **with its headers** (the `serve.py`
above) and a browser, so run them by hand after a change:

- **email-exposure**: walks `dist/`, fails if any address appears inside a
  `<script>` tag or in any non-HTML file. Exclude binary types: random bytes in
  an image will match an email regex.
- **site-audit**: Playwright across every page, every theme, a desktop and a
  phone width. Fails on a console or CSP error, horizontal overflow, a missing
  `h1`/`main`/description, a link with no accessible name, a wrong canonical, a
  link to a route that does not exist, WCAG AA contrast failures, touch targets
  under 24x24 CSS px, and focus obscured by sticky elements. Open every dialog
  and overlay too: they load code paths the page itself never runs.

A CSP error in the console is the fastest signal that the CSP broke (a hash
out of date under A, an inline style or a new origin under B), which is why
the audit is a security test and not only a quality one.

---

# PART 6: a Git-based CMS (Decap, Sveltia, …)

A Git-based CMS is a static admin page that authenticates a user against the
Git host and commits content straight into the repository. There is no CMS
server and no CMS database, which keeps the good property from the top of this
guide. What it adds is **one authenticated route and a write path into the
repository**, and that is the whole threat model.

## 6.1 Self-host the bundle, give the CMS its own CSP

Install the CMS as a pinned npm dependency and copy its bundle into the CMS
folder with a tiny script. The admin `index.html` loads only that local file:
no CDN script, so a compromised CDN cannot reach the publishing pipeline, and
updating is a deliberate act.

Give the CMS path **its own CSP** (Trap 1.3: never also a CSP under `/*`).
Even self-hosted, the bundle still reaches out to the Git host's API, avatar
and raw-content hosts; allow exactly those origins, per directive. The CMS UI
usually needs `style-src 'unsafe-inline'`; that is acceptable **only** because
it is scoped to the CMS path. Add `Cache-Control: no-store` and
`X-Robots-Tag: noindex, nofollow, noarchive` on the same block.

**Look inside the bundle, not only at the `<script>` tag.** A self-hosted CMS
bundle can still `import()` helpers at runtime from a public CDN (syntax
highlighters, EXIF parsers, Markdown converters, fonts). With
`script-src 'self'` those loads are blocked and the feature breaks silently;
with the CDN allowed, whoever controls the CDN controls the editor. Vendor the
helpers as exact dependencies and patch the loader's base URL at build;
`kekkai ./dist` reports runtime CDN references inside JavaScript.

## 6.2 Authentication without an OAuth proxy

For a single editor, a Git host **fine-grained personal access token** avoids
OAuth entirely: **Contents: read/write** on **this one repository only**, an
**expiry date** renewed on purpose, kept in a password manager and never in a
file, a commit, an env var or a chat. No Worker, no client secret, no third
party between the editor and the repository. Trade-off: the token is held in
the editor's browser storage while signed in, so sign out on shared machines.

With several editors, run your own small Worker as the OAuth proxy. The client
secret is a **Worker secret**, never a file or a build-time constant. Restrict
the OAuth app's callback URL to the exact admin URL. A shared third-party proxy
puts someone else in the publishing path.

## 6.3 Repository visibility is content visibility

A Git-based CMS commits content to the repository. If that repository is
public, so is every draft, every unpublished page and every piece of media.
Private repository, and audit who has write access: **write access is publish
access**.

## 6.4 Hide the CMS: unguessable path, NOT robots.txt

Do not add `Disallow: /admin` to `robots.txt`. It is public, and a `Disallow`
line advertises exactly where the admin lives. Instead:

- **An unguessable folder name** (a random string) instead of `/admin/`. Bots
  hammer `/admin/`, `/wp-admin/` and `/cms/` all day; a random path takes the
  CMS out of every scan.
- **`noindex` as a header** (`X-Robots-Tag` on the CMS path) **and** a meta
  tag.
- **The path appears in no public file**: not in `robots.txt`, not in the
  sitemap, not in navigation, not in client JS. Keep it in a build-time-only
  constant used by `astro.config.mjs` and the headers generator, never
  imported by a browser script. `kekkai ./dist --admin <folder>` checks it.
- **After moving it**, make sure the old folder can never deploy again:

  ```js
  // astro.config.mjs
  const dropOldAdmin = () => ({ name: 'drop-old-admin', hooks: {
    'astro:build:done': ({ dir }) => rmSync(new URL('admin/', dir), { recursive: true, force: true }) } });
  ```

- **Cloudflare Access on the CMS path** as defence in depth: one Access
  application with exactly `www.example.com/<cms-folder>/*` as its
  destination, Emails policy. An unauthenticated visitor then never even
  downloads the admin bundle. Afterwards check in a private window that the
  public pages still load without a login.

## 6.5 Content is executable at build time

Astro renders Markdown at build. If the content schema allows raw HTML in body
fields, anyone with CMS write access can put a `<script>` into the built pages.

- **Strategy A:** the post-build hasher will dutifully hash that script and
  **allow** it. Disallow raw HTML in content, or sanitise at render.
- **Strategy B:** an injected inline `<script>` or `style=""` is simply
  **blocked** by `script-src 'self'` / `style-src 'self'`. This is the
  strongest argument for B on a CMS site.

Either way, harden what content *can* do legitimately: a Markdown plugin that
gives every link in content `target="_blank" rel="noopener noreferrer"`,
skipping `#` anchors, footnotes, `mailto:` and `tel:`. With
`Referrer-Policy: no-referrer` outbound links then leak neither the opener nor
the referring page.

## 6.6 Media uploads

Every upload is a commit and the repository grows forever. Convert raster
uploads to WebP in the browser before the commit and cap file size, so no
camera originals reach the repository. Re-encoding through a canvas normally
drops EXIF, GPS included; confirm it with `exiftool` on a committed file before
relying on it. Constrain uploads to an allowlist of image types.

## 6.7 Code deliveries must never overwrite CMS content

Once a CMS edits content in the repository, the repository, not anyone's local
copy, is the source of truth for content. Code changes never include
CMS-managed folders unless that is the explicit task; pull right before
committing code and rebase rather than force-push; keep a `.gitignore` for
`node_modules/`, `dist/`, `.astro/`, `.env*`, and stage explicit paths.

## 6.8 The CMS config is public

`config.yml` is fetched by the browser, so it is public to anyone who finds
the admin path. It names the repository, branch and backend, which is
tolerable (6.4). Its **comments** are not: "private repo", "auth goes through
our Worker", "locally use the local backend" are reconnaissance. Strip
comments from served config files at build. Keep one-off importers that write
into the CMS content folders out of the repository (6.7); `kekkai ./repo`
flags scripts that write where editors publish.

## 6.9 After adding a CMS, re-run PART 5

The admin bundle, its configuration file and the media folder are all new
output. The config names the repository, the branch and the backend in plain
text, which is fine only because the path is unguessable, `noindex` and ideally
behind Access, and the repository is private.

---

# PART 7: what the repository itself discloses

The site output is one surface. The repository, its documentation and its
history are another, and they are read by anyone with access to the repo,
which for a public repo is everyone and for a private one is everyone who
ever had a token. `kekkai ./repo` runs the mechanical half of this part.

## 7.1 The principle

**What looks innocent to you can be a door for someone else.** Not writing
down keys is the obvious rule. The less obvious one is to write down as
little as possible about **how** the security is set up: what a key is
allowed to do, how login works, who has access, which emails, which
settings, which traps you fell into.

## 7.2 Rules (put them in the project's CLAUDE.md or CONTRIBUTING)

- **No key, token, password or secret value** in the repo, docs, comments,
  commits, PRs, issues, logs or chat. Not a fragment, not its **shape or
  prefix** ("the token starts with …"), not an example that looks real.
- Code and docs carry **only the names** of the variables, as far as the code
  needs them. One source for the names (for example an `astro:env` schema
  with `access: "secret"`). Docs point there; they do not repeat it.
- **Values only** in the platform's secret store (Worker secrets, Pages
  environment variables marked secret) and locally in `.env` / `.dev.vars`,
  which are in `.gitignore` and never committed.
- **Minimal description of the security infrastructure.** Write "locked down,
  configured on the host", not policy names, scopes, login method or lists of
  emails. Write "least privilege", not the exact permission or the app name.
- No secret in a URL, query string, client bundle or `PUBLIC_*` variable. No
  secret or personal data in logs.
- **Least privilege** for every token and every app.
- **Before every commit**, read the diff for keys and for references to them.
- **On suspicion of a leak:** rotate first, immediately. Clean history after
  (7.5).
- **Only `main` goes online**, through a merge (4.6).

## 7.3 Places that slip

- **Code comments.** "Admin API token (prefix …), server-side" is not a key,
  but it tells a reader what to search for and how to recognise it.
- **A public changelog or `/version` page.** Reachable by anyone who knows
  the address, `noindex` or not. Security-related entries are written
  neutrally ("housekeeping", "updated project notes"), never "closed the …",
  never a staging hostname.
- **Deploy guides.** They fill up with policy names, scopes, paths, login
  methods and "troubleshooting" sections that describe real traps. Keep the
  order of steps and *where* each thing is configured, nothing more.
- **Launch checklists.** Security lines stay general.
- **Account emails** (dev store, admin, partner accounts) in docs tell a
  phisher which account to target. They are not written down.
- **Names of apps and integrations** (custom apps, GitHub apps, OAuth apps)
  do not belong in docs.
- **Agent configuration files.** No `settings.local.json` or any settings
  file with keys inside the repo; no `.claude/` folder with credentials.
  Skills and `CLAUDE.md` are fine. Agent-side credentials live in the
  agent's own environment, outside the repo, and die with the session.

## 7.4 Preview and staging surfaces

A staging host or preview URL named in public output or in docs is a map to
the unfinished version of the site. The lock in front of it (Cloudflare
Access or equivalent) is configured with the **exact host** of each app,
never a wildcard over the whole domain (4.3). Access given for a preview is
removed after the release. 2FA on email, host, Git forge and any commerce
backend for everyone who has access.

## 7.5 Cleaning git history when something was committed

1. **Rotate first**, if the value was real. Cleaning alone is not enough.
2. Make sure nothing is lost: every branch pushed, nothing open.
3. Work on a **fresh clone in another folder** with `git filter-repo`
   (`pip install git-filter-repo`):

   ```bash
   git clone --no-local <repo> rewrite && cd rewrite
   printf '%s\n' 'regex:<pattern>==><replacement>' > ../repl.txt
   git filter-repo --force --refs main <other-branch> --replace-text ../repl.txt
   ```

4. **Verify:** `git grep -l '<pattern>' $(git rev-list --all)` returns
   nothing, and the tip tree is unchanged
   (`git rev-parse <branch>^{tree}` before and after).
5. **Force-push with a lease:**

   ```bash
   git push --force-with-lease=main:<old-hash> <url> main:main <other-branch>:<other-branch>
   ```

   If `main` is protected against force-push, lift the protection briefly and
   **put it back immediately**.
6. **Every local copy:** reset to the new refs, delete old branches,
   `git reflog expire --expire=now --all && git gc --prune=now`. Better: a
   fresh clone, copying only `.env` / `.dev.vars` over, then `npm ci`. Never
   keep the old folder around; one push from it brings the old history back.
7. **What a force-push does NOT clean:** the forge keeps `refs/pull/*/head`
   for every PR, and old commits stay reachable by hash. Only the forge's
   support team removes those. On GitHub: support → Repository features →
   Branches → Removing sensitive data. They need the repo name, what was
   rewritten (without repeating the value), the branches force-pushed and
   when, the full hash of the first changed commit
   (`git log --all --format='%H' -S'<pattern>' --reverse | head -1`), and the
   range of affected PRs. They only act on genuinely sensitive data; a request
   about non-secret descriptions is judged case by case. Check the repo is
   private and has zero forks first: forks keep the old history.
8. The deploy from `main` runs again; with the same tree at the tip, the
   site does not change.

## 7.6 The AI footprint

This one is not a vulnerability and it is said with regret. Code written with
AI assistants is new, and like everything new it ships with bugs and gaps; a
visible sign that a project was built that way is now read as "probably
unreviewed, probably soft", and such projects are being picked as targets.
Hiding the sign fixes nothing in the code; review and tests do that. But a
public repo or site does not have to volunteer the hint.

What gives it away, and what `kekkai` looks for:

- **Agent configuration files tracked in a public repo:** `CLAUDE.md`,
  `AGENTS.md`, `GEMINI.md`, `.claude/`, `.cursor/`, `.cursorrules`,
  `.windsurfrules`, `.clinerules`, `.aider*`, `.github/copilot-instructions.md`
  and relatives. They are useful; keep them **git-ignored**, or in a separate
  private repo, or in the agent's own project settings. If one must be
  tracked, it says how to build and test, not what the weak spots are.
- **Commit trailers and PR footers:** `Co-Authored-By: <assistant> …`,
  `🤖 Generated with …`, session links. A co-author trailer also puts the
  assistant's account into the repository's **Contributors** list and graph,
  which is the first thing a visitor sees. Remove the trailers from the commit
  template; for an existing history, rewrite the messages (below) before the
  repo goes public, and the contributor disappears with them.

  ```bash
  # drop the trailers from every commit message, keep trees and authorship
  git filter-repo --force --message-callback '
  import re
  # (keep the pattern ASCII: a bytes literal cannot hold the robot emoji)
  m = re.sub(rb"(?im)^(co-authored-by:.*(claude|copilot|chatgpt|gemini|cursor|codex|aider|devin).*|.*generated with \[claude code\].*|claude-session:.*)\n?", b"", message)
  return m.rstrip(b"\n") + b"\n"
  '
  git push --force-with-lease origin main
  git tag -f <tag> <new hash> && git push -f origin <tag>   # for each release tag
  ```
- **Attribution in output and docs:** a "built with <assistant>" line, a
  generator meta naming the tool, a `humans.txt` crediting it.
- **Served agent files:** `/CLAUDE.md`, `/AGENTS.md`, `/.cursorrules` or
  `/llms-ctx.txt` answering 200 on the live site, usually because the whole
  repo root was published.

`kekkai` reports all of this as a warning, in every mode. The remedy is the
same everywhere: say nothing about the tooling in anything public, and let
the code be judged on the review it actually got.

## 7.7 Quick checks

```bash
# settings or credential files tracked
git ls-files | grep -iE "settings|\.env|dev\.vars|secret|key"
# known key prefixes across all history (add your services' prefixes)
git grep -nIE "AKIA[0-9A-Z]{16}|BEGIN (RSA|EC|OPENSSH) PRIVATE|gh[pousr]_[A-Za-z0-9]{36}" $(git rev-list --all)
# security-infrastructure descriptions in docs and comments
git grep -nIiE "access polic|one-time pin|client secret|token scope|oauth app" -- '*.md' '*.ts' '*.mjs' '*.astro'
```

`kekkai ./repo` does the three of them, plus the AI footprint (7.6), `.gitignore` coverage, tracked
`.env` / `.dev.vars` / local settings, env files anywhere in history, docs
that name account emails or staging hosts, and comments that describe a
credential's shape.

---

# Verification checklist

The rule that matters more than any individual item: **verify the packaged
output and the live response, never your intention.**

- [ ] Live fingerprint (`version.txt` / commit SHA) matches what was just shipped
- [ ] Strategy A: every inline script's sha384 appears in its own page's CSP
      (recomputed from `dist/`, not assumed)
- [ ] Strategy B: no executable inline script and no `style=""` in `dist/`
      (outside the CMS); every HTML file matches a CSP rule in `_headers`
- [ ] No path receives two CSP headers (no CSP under `/*` when any path has its own)
- [ ] Every JSON-LD block parses
- [ ] Local tests ran against a server that applies `_headers`, zero console/CSP
      errors across pages, themes and dialogs
- [ ] Response headers checked on an HTML document **and** an asset, cache disabled
- [ ] No `access-control-allow-origin: *` on documents or assets
- [ ] HSTS `preload` present or absent **on purpose**
- [ ] Live `robots.txt` has nothing above your own lines and names no admin path
- [ ] AI crawler categories set deliberately and matching what `robots.txt` says
- [ ] Preview-host Access application lists **two** destinations; policy is
      Emails, not "all authenticated users"
- [ ] The custom domain loads normally in a private window
- [ ] Apex redirects to www (or the reverse) with a **301**, checked as a status code
- [ ] Leak audit clean: no source maps, no config files, no stack disclosure, no
      local paths, no forbidden strings, CMS path only in its folder and `_headers`
- [ ] CMS: self-hosted pinned bundle, own CSP, `no-store` + `noindex` header,
      private repo, fine-grained expiring token (or own OAuth Worker), Access on
      its path
- [ ] Production builds come from `main` only; a push to a working branch starts nothing
- [ ] `kekkai ./repo` clean: no credential shapes in the tree or the history, no
      tracked `.env` / local settings, docs describe *where* security is
      configured and not *how*, no account emails or staging hosts in docs
- [ ] Public changelog / version page carries no security details or staging hosts
- [ ] No AI-assistant footprint in public repo or output: agent config git-ignored,
      no AI co-author trailers, no "built with …" credit
- [ ] 2FA on every account with access; preview access removed after release;
      locks scoped to exact hosts
- [ ] `kekkai` live scan green after deploy
