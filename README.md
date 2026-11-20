<img width="2752" height="1536" alt="emblem-github" src="https://github.com/user-attachments/assets/edcc632b-da99-4691-9d43-7e0c06b454ff" />


# kekkai (結界)

Static site boundary & disclosure check.

In Japanese tradition, a *kekkai* (結界) is a protective barrier that defines a
boundary and keeps unwanted elements out. This tool acts as a perimeter check
for your static build: it scans a **live URL** or a **build folder** before
deployment to verify strict security headers, a CSP that matches the actual
HTML, zero stack disclosure in the output, and nothing served that should not
be.

One file, zero dependencies, Node 18+. Reference stack: Astro, built to static
files, on Cloudflare Pages (or any host that applies a `_headers` file at the
edge: Netlify, etc.). The checks are framework-agnostic, and they reach the
places a static or headless site actually leaks from: the **git repository**
behind it, a **server-rendered** build on Workers or Node, a **headless
backend** (Medusa, Shopify), a **self-hosted origin** behind nginx or
Cloudflare, its **cookies** and its **subdomains**.

```
npx github:kappa-yashi/kekkai https://www.example.com
npx github:kappa-yashi/kekkai ./dist
npx github:kappa-yashi/kekkai ./repo
npx github:kappa-yashi/kekkai check sharp@0.33.5 "sveltia cms"   # before you adopt it
```

or clone and run `node bin/kekkai.mjs <target>`.

## What it checks

**Live URL** (read-only GETs)

- http → https 301, apex → www 301 (status codes, not bodies); www must be
  the primary host — apex as primary, or both hosts answering 200, is a warning
- HSTS (age, includeSubDomains, preload flagged as a decision)
- Content-Security-Policy: present, single (not two policies on one path),
  `script-src` without `'unsafe-inline'` / `'unsafe-eval'` / wildcards / public
  CDNs, `object-src 'none'`, `base-uri`, `form-action`, `default-src`,
  `frame-ancestors`
- X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, COOP, CORP
- `Access-Control-Allow-Origin: *` on documents **and** assets
- Server / X-Powered-By version disclosure, `<meta name="generator">`
- inline `<script>` / `<style>` / `style=""` / `on*=` vs the CSP, evaluated the
  way a browser does: every policy on the response (header(s) **and** `<meta>`)
  enforced independently and intersected; `script-src-elem/attr` → `script-src`
  → `default-src` fallbacks; sha256/384/512 hashes recomputed on the exact
  element text; `nonce=` attributes checked against the policy;
  `'unsafe-inline'` ignored when hashes or nonces are present; attributes need
  `'unsafe-hashes'`. A CDN-injected inline script (per-request token, cannot be
  hashed) is a warning, not a failure
- JSON-LD parses; email addresses inside JSON-LD or text files (where email
  obfuscation cannot reach)
- third-party script origins; **Subresource Integrity** on every cross-origin
  script / stylesheet (`integrity=` + `crossorigin=`)
- inline event handlers (`onclick=`, `onload=` …) vs the CSP
- inline `<svg>` carrying `<script>` / `<style>` / external references; SVG
  files referenced by the page checked for scripts, handlers, `<foreignObject>`
- source maps that are actually served
- canonical absolute and on the same host
- robots.txt advertising private paths, managed blocks prepended by the host
- sitemap listing private-looking or foreign-host URLs
- well-known leak paths (`.git/HEAD`, `.env`, `package.json`, config files,
  `wp-login.php`, `admin/` …) with soft-404 detection
- a sample of inner pages (same-origin redirects followed and reported): CSP +
  HSTS present on every route, inline code consistent with each page's own
  policy
- **disclosure**: credential-shaped strings (known key prefixes, private key
  blocks, JWTs, secret assignments) in the document, its JS/CSS and the usual
  `/version` / `/changelog` routes; staging and preview hosts; vocabulary that
  describes the security setup; developer comments left in the HTML
- `/version.txt` build fingerprint and whether it is `no-store`
- with `--admin`: the CMS page (`no-store`, `noindex`, CSP, only same-origin
  code) and its public `config.yml` (telling comments, repository named)
- runtime CDN references inside the page's own JavaScript
- `/cdn-cgi/` assets recognised as Cloudflare-served, with the zone-level HSTS hint

**Build folder** (`dist/` with its `_headers`)

- parses `_headers` (Cloudflare/Netlify syntax, additive rules, `!` removals)
  and computes the effective headers of **every** HTML file
- every HTML file covered by a CSP rule; no CSP under `/*` colliding with a
  path CSP; a `public/_headers` next to a generated one
- all header checks above, per header profile
- inline scripts hashed against the policy; inline styles vs `style-src`
- source maps and `sourceMappingURL` comments; lockfiles, `.env`, config,
  `.git`, `README`
- local filesystem paths (`/home/x/`, `/Users/x/`, `C:\Users\x\`)
- `--forbid a,b,c`: strings that must not appear (codenames, staging hosts)
- `--admin <folder>`: the CMS folder name must appear nowhere outside itself
- repository links (listed, not judged: public release repos are content)
- email addresses in text files and inside `<script>`
- SRI, inline handlers and inline-SVG checks per header profile; every `.svg`
  file in the output scanned for `<script>`, handlers, `<foreignObject>`,
  external references
- `_redirects` parsed: open redirects (`https://:splat`), staging / preview
  hosts, proxy rules to another origin, hostname rules that Pages cannot match
- the same disclosure scan over every text file of the output
- comments in publicly served config files (`.yml`, `.toml`, `.json5`, the CMS
  `config.yml` included) that describe the setup
- runtime loads from public CDNs hidden inside JavaScript (`import()`,
  `fetch()` of unpkg / jsdelivr / esm.sh / cdnjs …): failure when the CSP lets
  them run, warning when it blocks them (that feature is broken)
- **AI footprint** (every mode, warning): agent config files (`CLAUDE.md`,
  `.claude/`, `.cursorrules`, `copilot-instructions.md` …) tracked or served,
  AI co-author / generator commit trailers, "built with …" attribution in
  output or docs — not a vulnerability, a targeting signal

**Repository** (a git working copy; detected by `.git`)

- tracked files that must never be tracked: `.env*`, `.dev.vars`, keys and
  certificates, `credentials.json`, `.claude/settings.local.json`, editor
  settings with secrets
- `.gitignore` coverage for `.env*`, `.dev.vars`, `node_modules`, `dist`,
  `settings.local.json`
- credential-shaped strings in every tracked text file
- docs that describe the security setup (access policies, login method, token
  scopes, OAuth apps), name staging hosts, or contain account email addresses
- code comments that describe a credential's shape ("token (prefix …)")
- **history**: credential shapes across all commits, `.env` / `.dev.vars`
  committed at any point, `--forbid` strings in history (`--no-history` skips)
- current branch and remote, with a reminder that production builds come
  from `main` only
- scripts that write into CMS-managed content folders (editors' work would be
  overwritten)
- `--forbid` hits in history reported per string with file count and the last
  commit that touched them

**Known incidents** (every mode, via [pwn.watch](https://pwn.watch))

- repo: every `name@version` from `package-lock.json` / `pnpm-lock.yaml` /
  `yarn.lock` (and pinned entries of `package.json`) is matched against the
  pwn.watch incident feed — patch-now advisories, breaches, supply-chain
  compromises. A version inside an affected range is a failure; an incident
  that names the package but whose affected range cannot be parsed is a
  warning to verify by hand
- dist / live: products visible in the output (generator meta, `Server` /
  `X-Powered-By`, `/_astro/`, `/_next/`, `wp-includes/…?ver=`, versioned
  library paths, the CMS bundle, site builders) are matched against **open**
  incidents; the version is usually not visible, so these are warnings that
  say which version is affected
- **decision gate**: `kekkai check <name>[@version] …` before `npm install`
  or before choosing a CMS / builder / platform — what pwn.watch has recorded
  for that name, open and closed, with fixed versions; exit 1 when the named
  version is inside an affected range
- the feed (`incidents.json`, ~1.5 MB) is downloaded once per run with an
  ETag cache in the system temp folder; **nothing about the scanned site is
  sent anywhere**. If pwn.watch is unreachable the cached copy is used, or the
  check is skipped with an info line. `--no-watch` disables it, `--watch-file`
  reads a saved feed (offline machines, CI, tests)

**Platform profile: Medusa** (auto-detected; `--platform medusa` forces it)

kekkai is for static sites, but a static storefront often sits on a
[Medusa](https://medusajs.com) backend — or on a custom commerce backend
built on it, which inherits every Medusa issue and fix. The profile adds:

- repo: `medusa-config.*` — hard-coded or fallback `jwtSecret` /
  `cookieSecret` (`|| "supersecret"`), catch-all CORS patterns, literal
  `databaseUrl` with a password, `rejectUnauthorized: false`, admin dashboard
  not disabled on the API host, `@medusajs/*` packages at mixed versions,
  custom API route groups outside `/store` `/admin` `/auth` with no
  middleware entry, `.env.template` files carrying real-looking values
- live, when the target answers like a Medusa Store API: publishable-key
  enforcement on `/store/*`, `/admin/*` closed (401), dashboard reachable at
  `/app`, CORS reflection of an unknown origin on store / admin / auth routes,
  `X-Powered-By`, HSTS and nosniff on the API, `.env` / `medusa-config` /
  upload-directory probes, stack traces in error bodies. The generic document
  checks are skipped for a JSON API; no senrigan hand-off
- storefront (live or build folder): a Medusa secret key (`sk_…`) in client
  code (fail), a local / staging / internal backend URL baked into the bundle
  (fail), the backend host listed so you scan it too (`--backend <url>` runs
  the backend checks in the same pass)
- `@medusajs/*` versions feed the known-incident check under the product
  name "medusa" (scoped packages match their product alias)

**Platform profile: Astro + headless Shopify** (auto-detected; `--platform shopify` forces it)

A storefront rendered by a Worker (Astro `output: 'server'` on Cloudflare
Workers) with Shopify as the commerce backend. Most pages exist only at
request time, the Worker holds API tokens, there are webhook endpoints, staff
tools behind an edge login, and a second storefront on `*.myshopify.com`. The
profile adds:

- repo: `wrangler.json(c)/.toml` with `workers_dev` / `preview_urls` not
  switched off (the Worker answers on `*.workers.dev` too, outside your
  domain's rules), secrets as plain `vars`, tokens declared client / public in
  Astro's env schema or read through `PUBLIC_*` variables, staff routes
  (`/tools`, `/admin`, `/internal` …) with no check in the middleware — edge-only
  protection —, webhook endpoints without a constant-time signature check or
  answering GET, no dedupe on the webhook id, a pinned Shopify API version out
  of its ~12-month support window, the private Storefront token or the Admin
  API in client code, private-token calls without `Shopify-Storefront-Buyer-IP`
- build output: an SSR build is recognised (only the prerendered pages are
  in the folder; the rest is checked live — the report says how to scan a
  local preview without deploying)
- live / build output: private Storefront token or Admin API URL in client
  code (fail), public token present (info: keep its scopes minimal), the
  store's `*.myshopify.com` handle — and in a live scan, whether that twin
  storefront is password-protected or redirects (an open one is a duplicate
  shop), `img-src` / `media-src` wider than `cdn.shopify.com`, forms posting to
  another host while `form-action` is `'self'` (checkout must leave by a server
  redirect)
- `@shopify/*` versions feed the known-incident check as "shopify"

**Public files, comments, changelogs** (every site)

- robots.txt: duplicates across user-agent groups collapsed; internal-sounding
  names (`tools`, `version`, `preview`, `backup` …) warned; in a live scan every
  Disallow path is requested — if the server itself answers 401/403, sends to a
  login (Cloudflare Access) or marks it `X-Robots-Tag: noindex`, the line only
  advertises a private path (fail), and edge-only protection is pointed out
- HTML comments: any comment that describes the build (file names, repo
  paths, CDN, tooling) is a warning, other comments are info; licence banners,
  conditional comments and framework markers are ignored
- public `/version` / `/changelog` pages: a warning when they name backend
  services (CRM, webhooks, Admin API, payment, mail …) or carry a full history —
  publish a build id and date (`version.txt`)
- `--forbid` hits in `_headers`, `_redirects`, `.assetsignore` are info: the
  host reads those files and does not serve them
- repo: tracked editor settings are a failure only when they hold
  credentials; `--private` (or `gh`, when installed, reporting the origin as
  private) turns staging hosts, account emails and AI footprint in docs into
  info
- inner pages: the scanned paths are listed, and a sitemap that names another
  host (scanning a local preview) is noted

**Cookies and subdomain takeover** (live)

- Cookies set by the scanned responses: `Domain=` (whole domain) is info for
  ordinary values and a warning for session-like ones (name like
  sess/sid/auth/token/jwt/csrf, or HttpOnly) — every subdomain can read and
  overwrite them; no `Secure` on https; `SameSite=None` (warning without
  `Secure`, browsers reject it); `__Host-` / `__Secure-` prefix rules broken
  (fail). Cookies written by JavaScript are not seen.
- `--subdomains`: names from certificate transparency (crt.sh — the one
  request that names the domain to a third party, so it is opt-in), or your
  own with `--subdomain-list a,b,c`. Each CNAME is resolved: a target that no
  longer exists is a **dangling CNAME** (fail); a target that answers with a
  known "unclaimed" page is matched against the
  [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
  fingerprints (fetched weekly, built-in fallback) — fail only where that list
  says the service is vulnerable, warning otherwise. When cookies are set for
  the whole domain, the takeover message says the claimed subdomain would
  read and overwrite them. `--resolver <ip>` picks the DNS server.

**Accuracy: what is not reported, and how unreachable targets are handled**

- Hosted platforms (Shopify, Wix, Webflow, site builders): an incident counts
  only when it is *about* the platform, not about another company that runs
  its shop on it; a real platform incident is info — the vendor patches it
  for everyone.
- Unknown URLs that redirect (to the home page or anywhere) are a soft 404
  too: a warning. A `_headers` / `_redirects` served as a file means the host
  does not read it — the report says so instead of only "served". Sites
  built and hosted on Lovable are recognised (`/__l5e/` assets).
- Single-page apps that answer every path with their shell: probes,
  version/changelog routes and text files are compared by type, `<title>`
  and size (bodies differ per request), so the shell is not reported as a
  served `_headers`, `Dockerfile` or changelog. CDN cookies (`__cf_bm`,
  `cf_clearance`, load-balancer cookies) are listed as the CDN's, not judged
  as the site's.
- Repo checks follow relative imports one level: an Access-JWT check or a
  constant-time comparison (library call or XOR-accumulate loop) in a helper
  the middleware or the route imports now counts.
- Edge-injected inline scripts name the Cloudflare feature and the switch:
  JavaScript Detections / Bot Fight Mode, Rocket Loader, Email Address
  Obfuscation, Web Analytics automatic setup, Zaraz.
- A target that cannot be reached is **NOT CHECKED** (exit 2) with the real
  cause, not BOUNDARY BROKEN; behind a proxy the report says Node's fetch
  needs `NODE_USE_ENV_PROXY=1`.
- Build folder: a sitemap that robots.txt declares but the build lacks is a
  warning (info on an SSR build — check it live); `/version`, `/version.json`,
  `/build.txt` are recognised as build fingerprints.

**TLS, Cloudflare SSL mode, nginx** (live)

- TLS: days until the certificate expires (! under 14, ✖ expired — the
  silent certbot failure), chain validity, TLS 1.0 / 1.1 still accepted (with
  the nginx line or the Cloudflare setting that turns them off).
- Behind Cloudflare: the SSL/TLS mode is not visible from outside, so the
  report says what Full (strict) needs. A redirect loop is reported as the
  signature of "Flexible" with an origin that redirects to https.
  `--origin <ip-or-host>` checks the origin itself: is its certificate valid
  for the domain (Cloudflare Origin CA or public) — Full (strict) ready — and
  does it serve the site to direct requests, around Cloudflare's WAF.
- nginx: the built-in error page (names the server even with
  `server_tokens off`), `/nginx_status` / `/stub_status`, directory listing on
  common asset folders, proxy headers (`Via`, `X-Upstream`, `X-Backend-Server`,
  `X-Served-By` …) that name internal addresses or ports.

**Self-hosted origins** (live)

- Transport: the bare IP of the host is requested — if it hands out the
  site, unknown hostnames are served too (default server missing); the TLS
  certificate's other names are listed (info). Skipped behind Cloudflare and
  for local addresses.
- Assets missing headers that the document has, on nginx: a hint about
  `add_header` inheritance (a location with its own `add_header` drops the
  inherited ones).
- Leak probes also try server and deploy files (`nginx.conf`, redirect maps,
  `.htaccess`, `Caddyfile`, `docker-compose.yml`, `Dockerfile`, `deploy.sh`,
  `.npmrc`).
- Known incidents: a `Server` version from a distribution package
  (`nginx/1.24.0 (Ubuntu)`) is a warning, not a failure — distributions
  backport fixes without changing the version; check the package changelog.
- Fewer false positives: the generator meta is read as a product name
  (`Astro v7.4.7` → astro); lockfile packages match an incident only on
  package-level evidence (a scoped package's bare name — `core`, `store` — is
  no longer an alias); `.npmrc` with settings only is info; local development
  connection strings (`localhost`, `127.0.0.1`, `host.docker.internal`) in
  example env files are not secrets; scanning a staging host, its own
  hostname in its pages is info; `--backend` with `--platform medusa` scans the
  target as the storefront and the backend separately.

## Options

```
Output
  --json              machine-readable output
  --summary           only warnings and failures, one line each, plus counts
  --out <file>        also write the report (.json / .md / .txt)
  --strict            warnings count as failures (exit 1)
  --version           print the version

Live
  --pages N           sample N inner pages from the sitemap (default 5)
  --no-probe          skip the leak-path probes
  --accept-edge-inline  a CDN-injected inline script (Cloudflare JS detections …) is info instead of warning
  --origin <ip|host>  behind Cloudflare: check the origin directly (Full (strict) ready? reachable around Cloudflare?)
  --subdomains        check subdomains from certificate transparency for dangling CNAMEs / takeover (asks crt.sh)
  --subdomain-list a,b  check these subdomains instead (no crt.sh request)
  --resolver <ip>     DNS server for the subdomain checks
  --backend <url>     storefront scan: also run the Medusa backend checks against this API host

Build folder / repository
  --repo | --dist     force the mode for a folder
  --admin <folder>    the CMS/admin folder name
  --forbid a,b,c      strings that must not appear in the output (whole tokens)
  --no-history        repo: skip the git-history scan
  --private           repo: the origin is private (docs / AI-footprint findings become info)

Profiles and feeds
  --platform medusa|shopify   force a platform profile (auto-detected otherwise)
  --no-watch          skip the known-incident check (no request to pwn.watch)
  --watch-file <f>    match against a saved incidents.json instead of fetching (offline / CI)
  --no-update-check   skip the daily check for a newer kekkai release
```

Exit code 0 = boundary holds, 1 = boundary broken, 2 = usage error or
**NOT CHECKED** (the target could not be reached — the report gives the cause
and concludes nothing).

## What kekkai sends out

Nothing about the site you scan leaves your machine except the requests to
the site itself. The other requests:

| to | when | what |
|---|---|---|
| `api.github.com` | every run, cached a day | newest kekkai tag (`--no-update-check` skips) |
| `pwn.watch` | every run, ETag-cached | the public incident feed; matching is local (`--no-watch` skips) |
| `raw.githubusercontent.com` | with `--subdomains`, cached a week | takeover fingerprints (can-i-take-over-xyz) |
| `crt.sh` | only with `--subdomains` | the domain name, to list certificate names |

## Local preview with real headers

`astro preview` and `python -m http.server` do not apply `_headers`. The guide
ships a 20-line `serve.py` that does; scan `http://127.0.0.1:4399` and the
transport checks are skipped automatically. For a server-rendered build
(Astro `output: 'server'` on Workers or Node), the build folder holds only
the prerendered pages: run the framework's preview with the secrets in a
`.dev.vars` next to the generated `wrangler.json`, scan
`http://localhost:<port>/<page>`, then stop it and delete that `.dev.vars`.

## One boundary, two tools

kekkai asks *what does the site give away?* Its twin,
[senrigan (千里眼)](https://github.com/kappa-yashi/senrigan), asks *what does the
site fail to tell the machines that should find it?* — titles, canonicals,
hreflang, sitemap, structured data. A site nobody can find has failed as
completely as one that was broken into; the breach announces itself, the
invisibility never does. Every kekkai report ends with the senrigan command
for the same target, and senrigan hands the transport findings (http, two
hosts answering, mixed content, apex as primary) back to kekkai.

## Start a project right: `kekkai init`

```
npx github:kappa-yashi/kekkai init . --admin <cms-folder>
```

Scaffolds, without touching existing files unless `--force`:

- `scripts/kekkai-postbuild.mjs` — after `astro build`, writes `dist/_headers`
  from the HTML that was actually built (one CSP block per route group, never
  under `/*`, cache rules, the CMS block with its own CSP + `no-store` +
  `noindex`), writes `version.txt` (`no-store`) from `package.json` +
  `CF_PAGES_COMMIT_SHA`, strips comments from served `.yml`/`.toml`, and fails
  if `public/_headers` exists. Edit the CONFIG block at the top.
- `.gitignore` block (`.env*`, `.dev.vars`, `*.local.json`, agent folders,
  `dist/`, `.astro/`).
- `kekkai-rules.md` — a copy of `reference/build-rules.md`: DO/DON'T rules for
  whoever writes the code, human or assistant, one line per check. Give it to
  the assistant before the first component.
- `package.json` `"build"` gets the post-build step when it is exactly
  `astro build`; otherwise it prints what to add.

Then set `build.inlineStylesheets: 'never'`, `vite.build.assetsInlineLimit: 0`
and `markdown.syntaxHighlight: false` (or a class-based highlighter) in
`astro.config.mjs`.

## As a Claude skill

This repository is also a skill: `SKILL.md` tells Claude to run the scanner,
how to read the report, and in which order to fix things;
`reference/build-rules.md` holds the rules to write by; `reference/hardening.md` is the long-form guide (headers template, two CSP
strategies with code, build fingerprint, host-dashboard traps, leak audit, the
threat model of a Git-based CMS, and what the repository itself discloses:
secrets, docs, changelogs, history rewriting, platform profiles, self-hosted
origins, cookies and subdomains). Copy the folder to `~/.claude/skills/kekkai`
or add it to your project's skills. An installed skill is a copy: the skill
starts every session by fetching the newest kekkai and says when the copy
you installed is behind — replace the folder then.

## Limits

- Not a vulnerability scanner for server-side applications, and not for
  WordPress: it checks the boundary of static and headless sites and the
  servers directly in front of them.
- Read-only: GET, OPTIONS and TLS handshakes. No forms, no logins, no
  brute force; rate limits on logins are not tested.
- Cookies written by JavaScript are not seen (no headless browser).
- Cannot see your host dashboard (bot rules, Access policies, managed
  robots.txt); it only observes the effects.
- Unknown options exit with code 2 and a suggestion; a target never starts with `-`.
- Emails inside licence/copyright headers of vendored code are not reported.
- Nonces inside `<meta>` CSPs are not honoured by browsers; header nonces are verified against the element's `nonce=` attribute.
- Credential detection is by shape; a secret that looks like plain text is
  invisible to it, and a hit is not proof the key is still valid. Rotate anyway.
- Only scan sites you own or are allowed to test.

## Licence

- Code (`bin/`, `package.json`) and `SKILL.md`: [MIT](LICENSE).
- The guide `reference/hardening.md`: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) —
  reuse and adapt it freely, credit **kappa.yashi** and link to the source.
