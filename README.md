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
```

or clone and run `node bin/kekkai.mjs <target>`.

## What it checks

**Live URL** (read-only GETs)

- http → https 301, apex ↔ www 301 (status codes, not bodies)
- HSTS (age, includeSubDomains, preload flagged as a decision)
- Content-Security-Policy: present, single (not two policies on one path),
  `script-src` without `'unsafe-inline'` / `'unsafe-eval'` / wildcards / public
  CDNs, `object-src 'none'`, `base-uri`, `form-action`, `default-src`,
  `frame-ancestors`
- X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, COOP, CORP
- `Access-Control-Allow-Origin: *` on documents **and** assets
- Server / X-Powered-By version disclosure, `<meta name="generator">`
- inline `<script>` vs the CSP: every hash recomputed, blocked scripts
  reported; `style=""` vs `style-src`
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
- a sample of inner pages: CSP + HSTS present on every route, inline code
  consistent with each page's own policy
- **disclosure**: credential-shaped strings (known key prefixes, private key
  blocks, JWTs, secret assignments) in the document, its JS/CSS and the usual
  `/version` / `/changelog` routes; staging and preview hosts; vocabulary that
  describes the security setup; developer comments left in the HTML
- `/version.txt` build fingerprint and whether it is `no-store`

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

## Options

```
--json              machine-readable output
--strict            warnings count as failures (exit 1)
--no-probe          live: skip the leak-path probes
--pages N           live: sample N inner pages from the sitemap (default 5)
--no-history        repo: skip the git-history scan
--accept-edge-inline  live: a CDN-injected inline script (Cloudflare JS detections) is info, not failure
--repo | --dist     force the mode for a folder
--admin <folder>    dist: the CMS/admin folder name
--forbid a,b,c      strings that must not appear in the output
```

Exit code 0 = boundary holds, 1 = boundary broken, 2 = usage.

## Local preview with real headers

`astro preview` and `python -m http.server` do not apply `_headers`. The guide
ships a 20-line `serve.py` that does; scan `http://127.0.0.1:4399` and the
transport checks are skipped automatically.

## As a Claude skill

This repository is also a skill: `SKILL.md` tells Claude to run the scanner,
how to read the report, and in which order to fix things;
`reference/hardening.md` is the long-form guide (headers template, two CSP
strategies with code, build fingerprint, host-dashboard traps, leak audit, the
threat model of a Git-based CMS, and what the repository itself discloses:
secrets, docs, changelogs, history rewriting). Copy the folder to `~/.claude/skills/kekkai`
or add it to your project's skills.

## Limits

- Not a vulnerability scanner for server-side applications.
- Cannot see your host dashboard (bot rules, Access policies, managed
  robots.txt); it only observes the effects.
- Nonces cannot be verified statically.
- Credential detection is by shape; a secret that looks like plain text is
  invisible to it, and a hit is not proof the key is still valid. Rotate anyway.
- Only scan sites you own or are allowed to test.

## Licence

- Code (`bin/`, `package.json`) and `SKILL.md`: [MIT](LICENSE).
- The guide `reference/hardening.md`: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) —
  reuse and adapt it freely, credit **kappa.yashi** and link to the source.
