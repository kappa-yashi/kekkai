---
name: kekkai
description: kekkai (結界) — static site boundary & disclosure check. Scans a live URL or a dist/ folder for strict security headers, a CSP that matches the actual HTML, stack disclosure in the output, exposed source maps and config files, robots/sitemap leaks, then walks through fixing what it finds. Use before a static site (Astro / Cloudflare Pages / Netlify) goes live, after any change to _headers or the CSP, or when asked "is this site hardened?".
---

# kekkai (結界) — static site boundary & disclosure check

A *kekkai* is a protective barrier that defines a boundary and keeps unwanted
elements out. This skill is the perimeter check for a static build.

A static site with no database, no server-side app, no accounts and no admin
surface is not a limitation; it is the security property. This skill checks
that the site actually ships with that property intact and that nothing in the
output or the response headers gives it away.

Two questions, opposite answers:

- **What the site does** (content, semantics, structured data): wide open.
- **How the site is built** (stack, repositories, endpoints, admin surfaces,
  hosting internals): invisible. Every disclosure is free reconnaissance.

## Scope

- Static output on an edge host (Cloudflare Pages, Netlify, or similar) with
  headers set through a `_headers` file or the host dashboard.
- Astro is the reference stack; the checks are framework-agnostic.
- Only scan sites you own or are allowed to test. The live scan is read-only
  GETs, but a handful of them probe well-known leak paths.

## Workflow

1. **Run the scanner.** It needs Node 18+ and nothing else.

   ```bash
   node bin/kekkai.mjs https://www.example.com      # live
   node bin/kekkai.mjs ./dist                        # build output + _headers
   node bin/kekkai.mjs ./repo                        # git working copy: secrets, ignored files, docs that describe the security setup
   node bin/kekkai.mjs ./dist --admin <cms-folder> --forbid codename,staging-host
   ```

   `--json` for machine output, `--strict` to make warnings fail, `--no-probe`
   to skip the leak-path probes, `--pages N` to sample N inner pages,
   `--no-history` to skip the git-history scan in repo mode.

   If the skill was installed without the script, fetch it from
   `https://github.com/kappa-yashi/kekkai` (`bin/kekkai.mjs`, zero
   dependencies) or run `npx github:kappa-yashi/kekkai <target>`.

2. **Read the report top to bottom.** `✖` is a failure, `!` a weakness worth a
   decision, `·` a fact. Exit code 1 means the boundary is broken.

3. **Fix in this order** (later steps depend on earlier ones):
   1. choose the CSP strategy (`reference/hardening.md`, PART 2)
   2. `_headers` (PART 1)
   3. CSP (PART 2)
   4. build fingerprint (PART 3)
   5. host dashboard audit (PART 4) — things no file in the repo can see
   6. build-output leak audit (PART 5)
   7. CMS surface, if any (PART 6)
   8. repository and docs hygiene (PART 7) — what the repo itself discloses

4. **Verify against the live response, not against intent.** On edge hosts a
   fix that looks obviously correct can silently do nothing. After deploy, run
   the live scan again and confirm the build fingerprint changed.

## How to read the important findings

| finding | what it means | fix |
|---|---|---|
| CSP missing on an inner page | the route is not in the `_headers` path list | add the path pattern; make the build check coverage (PART 5) |
| N CSP policies on one response | a `/*` rule **and** a path rule — rules are additive, browsers enforce the intersection | never put a CSP under `/*` when any path has its own |
| inline script not allowed by CSP | the browser blocks it (Strategy B) or a hash is stale (Strategy A) | move it to a bundled/external file, or regenerate hashes on every build |
| `style=""` but `style-src 'self'` | styles are silently dropped | data attributes + CSS, or CSSOM from an allowed script |
| `Access-Control-Allow-Origin: *` | any site's JS may read your responses | remove it (`! Access-Control-Allow-Origin` on Pages) or set your own origin; **verify live**, the removal is not always honoured |
| `frame-ancestors` in a `<meta>` CSP | ignored by browsers | it must be a real header |
| robots.txt names an admin path | `Disallow` advertises it to the world | unguessable folder name + `X-Robots-Tag: noindex` header, path in no public file |
| source map public | original source one request away | drop `.map` from the output and the `sourceMappingURL` comment |
| third-party script origin | that host can run anything on the page | self-host, or pin with SRI; keep `script-src 'self'` |
| cross-origin script without `integrity=` | the CDN can swap the file | add `integrity="sha384-…" crossorigin="anonymous"`, or self-host |
| inline event handler | blocked by a `'self'`/hash CSP and an XSS sink | `addEventListener` in a bundled module |
| `<script>` inside an SVG | executes when inlined or embedded as `<object>` | strip it; serve untrusted SVGs only as `<img>` |
| open redirect in `_redirects` | `https://:splat` sends users anywhere | fixed destination hosts only |
| credential-shaped string (output, tree or history) | a key is public, or was | **rotate first**, then remove; history needs `git filter-repo` + forge support (PART 7.5) |
| staging / preview host in output or docs | a map to the unfinished site | remove; lock previews with exact-host Access |
| docs describe the security setup | policies, scopes, login method, app names, account emails are reconnaissance | docs say *where* it is configured, not *how* (PART 7.2–7.3) |
| tracked `.env` / `settings.local.json` / `.claude/*.json` | local credentials in the repo | untrack, `.gitignore`, rotate |
| developer HTML comment | TODO/password/admin notes shipped to every visitor | strip comments in the build |
| HSTS preload on | one-way door for the whole domain | keep only if it was a decision for this domain |
| no `version.txt` | "is the new build live?" has no one-request answer | ship a `no-store` fingerprint (PART 3) |

## Reference

`reference/hardening.md` is the long-form guide: a `_headers` template, the
two CSP strategies with code, the build fingerprint, the host-dashboard traps,
the leak-audit script and the Git-based CMS threat model. Read the part that
matches the finding; do not read it all for a green report.

## What this skill does not do

- It is not a vulnerability scanner for server-side applications.
- Credential detection is by shape (known prefixes, key blocks, assignments). It cannot see a secret that looks like ordinary text, and it cannot know whether a match is still valid — treat every hit as live until rotated.
- It cannot see your host dashboard (bot rules, Access policies, managed
  robots.txt injection). PART 4 is a checklist for that; the live scan only
  observes the effects.
- It does not verify nonces (they change per response).
