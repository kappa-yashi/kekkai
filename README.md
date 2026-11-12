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
edge: Netlify, etc.). The checks are framework-agnostic.

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

## Options

```
--json              machine-readable output
--summary           only warnings and failures, one line each, plus counts
--out <file>        also write the report (.json / .md / .txt)
--strict            warnings count as failures (exit 1)
--no-probe          live: skip the leak-path probes
--pages N           live: sample N inner pages from the sitemap (default 5)
--no-history        repo: skip the git-history scan
--accept-edge-inline  a CDN-injected inline script (Cloudflare JS detections) is info instead of warning
--repo | --dist     force the mode for a folder
--admin <folder>    dist: the CMS/admin folder name
--forbid a,b,c      strings that must not appear in the output
--no-watch          skip the known-incident check (no request to pwn.watch)
--platform medusa   force the Medusa profile (auto-detected otherwise)
--backend <url>     storefront scan: also run the Medusa backend checks against this API host
--watch-file <f>    match against a saved incidents.json instead of fetching (offline / CI)
```

Exit code 0 = boundary holds, 1 = boundary broken, 2 = usage.

## Local preview with real headers

`astro preview` and `python -m http.server` do not apply `_headers`. The guide
ships a 20-line `serve.py` that does; scan `http://127.0.0.1:4399` and the
transport checks are skipped automatically.

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
secrets, docs, changelogs, history rewriting). Copy the folder to `~/.claude/skills/kekkai`
or add it to your project's skills.

## Limits

- Not a vulnerability scanner for server-side applications.
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
