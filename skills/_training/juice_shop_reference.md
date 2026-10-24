---
test_mode: training_only     # NEVER loaded into a live engagement's system prompt.
                              # Excluded from base_agent.py's skill-loading path and from
                              # Part 1's skill catalog selection by this flag alone.
owasp_id: N/A
vuln_class: N/A
source: OWASP Juice Shop v20 (80/112 challenges solved)
purpose: Calibration / regression reference only — exact routes, creds, and keys
         for re-validating ARGUS against a known app. Not technique guidance.
---

# Reference: OWASP Juice Shop (Training Target)

Irreducibly target-specific artifacts extracted from the former
`skills/webapp_exploitation/SKILL.md`. Kept for regression testing ARGUS
against Juice Shop, never for live engagements — the generalizable technique
behind each item now lives in the matching `skills/owasp_top10/<category>/`
file instead.

## Obfuscated / hidden routes (px.png scheme)
- `/1px.png` → Score Board (`/#/score-board`)
- `/11px.png` → Web3 Sandbox (`/#/web3-sandbox`)
- `/19px.png` → Admin Section (`/#/administration`)
- `/56px.png` → Token Sale
- `/81px.png` → Privacy Policy (`/#/privacy-security/privacy-policy`)
- Trigger with a `Referer` header pointing to the matching Angular route.

## Hardcoded credentials / test accounts
- `testing@juice-sh.op` / `IamUsedForTesting`
- `bender@juice-sh.op` (known email for auth-bypass SQLi demo)
- `acc0unt4nt@juice-sh.op` / hash `1f5aba774eb3bf7ae03d7a2b6d55ce62`
- Common cracked passwords seen in this build: `admin123`, `ncc-1701`,
  `OhG0dPlease1`, `slurmCl4ssic`

## Exact vulnerable endpoints
- `GET /rest/track-order/<payload>` — NoSQL `$where` injection
- `PATCH /rest/products/reviews` — unauthenticated ownership bypass
- `PUT /api/Products/9` — stored XSS via description field
- `POST /api/Feedbacks/` — UserId tampering, CAPTCHA reuse
- `GET /rest/basket/2` — IDOR on basket by ID
- `PUT /api/BasketItems/1` — negative-quantity business logic bypass
- `POST /profile/image/url` — SSRF + CSP-bypass fallback-store behavior
- `GET /encryptionkeys/jwt.pub` — exposed RSA public key used for HS256 confusion
- `POST /dataerasure/` with `layout=../package.json` — Handlebars path traversal
- `GET /rest/user/whoami?fields=password` / `?callback=foo` — field-selection + JSONP leaks
- Challenge-key confirmation: `GET /api/Challenges/?key=<key>` after each attempt
- Challenge unlock key literal: `tRy_H4rd3r_n0thIng_iS_Imp0ssibl3`

## Exact file/library version pin
- `sanitize-html@1.4.2` — the specific vulnerable version; the *bypass pattern*
  (tag-soup double-tag confusion) generalizes and now lives in
  `skills/owasp_top10/a03_injection/xss_stored_blackbox_SKILL.md`.

## FTP artifacts
`acquisitions.md`, `eastere.gg`, `package.json.bak`, `coupons_2013.md.bak`,
`suspicious_errors.yml` (null-byte bypass: `/ftp/suspicious_errors.yml%2500.md`)

## OSINT / privacy challenge specifics
EXIF metadata geo-stalking challenge, security-question answers derived from
a fictional user's public profile — Juice Shop's own challenge content, not
a generalizable recon technique.

---
**Do not promote any of the above back into a live skill file.** If ARGUS is
re-run against this training target for regression testing, this file may be
loaded explicitly by name — it must never be picked up by normal test_mode /
relevance-based skill selection.
