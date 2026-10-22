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

## Options

```
--json              machine-readable output
--strict            warnings count as failures (exit 1)
--no-probe          live: skip the leak-path probes
--pages N           live: sample N inner pages from the sitemap (default 5)
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
threat model of a Git-based CMS). Copy the folder to `~/.claude/skills/kekkai`
or add it to your project's skills.

## Limits

- Not a vulnerability scanner for server-side applications.
- Cannot see your host dashboard (bot rules, Access policies, managed
  robots.txt); it only observes the effects.
- Nonces cannot be verified statically.
- Only scan sites you own or are allowed to test.

## Licence

- Code (`bin/`, `package.json`) and `SKILL.md`: [MIT](LICENSE).
- The guide `reference/hardening.md`: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) —
  reuse and adapt it freely, credit **kappa.yashi** and link to the source.
