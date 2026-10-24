---
owasp_id: A05:2021
vuln_class: security_misconfiguration
test_mode: blackbox
requires: []
primitive: misconfig_exposed
evidence_schema:
  required_proof: [exposed_resource_sample, config_detail_disclosed]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Security Misconfiguration — Black Box

## 1. Recon — Attack Surface Mapping
- Default/sample paths: `/admin`, `/.env`, `/.git/`, `/metrics`,
  `/actuator`, `/swagger`, `/.well-known/`, `/debug`, `/phpinfo.php`,
  backup/old files (`.bak`, `.old`, `~`).
- Verbose error pages (stack traces, framework version banners) triggered
  by malformed input.
- Security headers on every response: CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, `Strict-Transport-Security`, CORS
  (`Access-Control-Allow-Origin: *` especially combined with
  `Allow-Credentials: true`).

## 2. Detection Methodology — Probe Sequence
1. Directory/file enum for the default-path list above via
   `tool_wrappers/gobuster.py`/`feroxbuster` with a config-aware wordlist.
2. Force a verbose error: malformed JSON body, wrong Content-Type, an
   obviously invalid param type — check if the response leaks a stack
   trace, file paths, or framework/version info.
3. Check CORS: send `Origin: https://evil-test.example` and inspect whether
   it's reflected back in `Access-Control-Allow-Origin` — especially
   dangerous combined with `Allow-Credentials: true`.
4. Check for default credentials on any admin/management interface found
   (Grafana, phpMyAdmin, Jenkins, cloud consoles) — try common default
   pairs only, never brute force broadly.

## 3. Exploitation Path — Tool Invocation
```python
import tool_wrappers.gobuster as gobuster
dirs = await gobuster.run(target, wordlist="config-paths.txt")
```
- `nuclei` has dedicated misconfiguration detection templates
  (`nuclei.run(target, mode="detect")`, already run in active recon) —
  cross-reference its hits for `exposure`/`misconfig`/`default-login`
  template families before manual probing.
- For any exposed `.env`/config endpoint found, capture only enough of the
  content to prove exposure — don't exfiltrate the full secret inventory
  into the report (Part 6 evidence hygiene handles redaction, but minimize
  at capture time too).

## 4. Evidence Capture
`evidence_schema` requires `exposed_resource_sample` (the response proving
the resource/endpoint is reachable — status 200 with real content, not a
404) AND `config_detail_disclosed` (the specific sensitive detail: a stack
trace with a file path, a reflected wildcard CORS origin, a default-login
success).

## 5. False-Positive Filtering
- An exposed endpoint that returns real content but is explicitly intended
  to be public (a status page, a public API docs page without sensitive
  detail) isn't a finding — confirm actual sensitivity of what's exposed.
- CORS reflecting `Origin` without `Allow-Credentials: true` is lower risk
  (no cookie-based session theft via it) — don't score it the same as the
  credentialed-reflection case.

## 6. CVSS Vector Construction
- Verbose error/stack trace disclosure alone (info only, no further access):
  `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (~Low/Medium).
- Exposed `.env`/config file with live credentials: `C:H` at minimum,
  often chains to a higher-severity finding once those credentials are
  tested (see Part 4 chain detection) — score the exposure itself as High,
  note the chain potential separately.
- CORS wildcard + credentials allowed, demonstrated session-reading cross
  origin: `S:C/C:H` (~8+ High).
- Default admin credentials granting management-interface access: Critical
  if that interface controls infrastructure/deployment.

## 7. Remediation (by stack)
- Disable verbose error pages / debug mode in production (`DEBUG=False`
  Django, `NODE_ENV=production` disabling stack traces, Flask
  `app.debug=False`).
- Never serve `.env`/`.git`/build artifacts from the web root; exclude via
  web server config (`nginx` `location ~ /\. { deny all; }`) and build
  pipeline (don't copy `.env` into the deploy artifact at all).
- CORS: explicit origin allowlist, never `*` combined with credentials.
- Rotate any credentials found in an exposed config file immediately, not
  just as a remediation recommendation — flag to the operator as urgent.
