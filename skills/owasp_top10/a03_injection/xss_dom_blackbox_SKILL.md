---
owasp_id: A03:2021
vuln_class: xss_dom
test_mode: blackbox
requires: []
primitive: xss_dom_confirmed
evidence_schema:
  required_proof: [sink_identified, execution_confirmation]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: DOM-Based XSS — Black Box

## 1. Recon — Attack Surface Mapping
- Target client-side-only rendering: SPA routes that read `location.hash`,
  `location.search`, or `window.name` and write them into the DOM without a
  server round-trip — `/#/?q=<payload>` never even reaches the server, so
  server-side logs/WAFs won't see it.
- Pull JS bundle URLs from `httpx`/crawl output; `linkfinder` output
  (already collected) often surfaces the exact sink function names.
- Prioritize search boxes, client-side routers, and any feature that
  manipulates the URL fragment to drive UI state (common in Angular/React/Vue
  SPAs).

## 2. Detection Methodology — Probe Sequence
1. Inject a canary into the URL fragment/query (`#q=argus_dom_test`,
   `?redirect=argus_dom_test`) and inspect the rendered DOM (not the HTTP
   response — DOM XSS never shows up in server response source).
2. Use the browser's dev tools / Playwright's `page.content()` *after*
   client-side JS has run, not the initial server HTML.
3. If the canary appears in the live DOM unescaped (inside `innerHTML`, not
   as a text node), it's a candidate sink.
4. Identify the specific sink via Playwright's `page.evaluate()` to inspect
   whether the write happened via `innerHTML`, `document.write`,
   `eval`, or a templating directive in unsafe mode (Angular's bypassSecurityTrust*, Vue `v-html`).

## 3. Exploitation Path — Payload + Verification
- Standard payload family: `<img src=x onerror=alert(1)>` works into most
  `innerHTML` sinks; for `javascript:` URL sinks (anchor `href` built from
  user input): `javascript:alert(1)`.
- Use `ExecutionMonitor` exactly as in reflected XSS §3 — DOM XSS still
  needs a real browser execution confirmation, canary presence in the DOM
  is not sufficient.
```python
async with ExecutionMonitor(page) as monitor:
    await page.goto(f"{target}/#/?q=<img src=x onerror=alert(1)>")
    events = await monitor.check_execution(wait_ms=1500)
```

## 4. Evidence Capture
`evidence_schema` requires `sink_identified` (which DOM API consumed the
tainted value — `innerHTML`, `eval`, `document.write`, or the specific
unsafe framework directive) AND `execution_confirmation` (Playwright dialog
trigger). Capture the fragment/query URL used — this is the entire PoC for
DOM XSS, no request/response pair needed since it never left the browser.

## 5. False-Positive Filtering
- Framework sinks that look dangerous by name but auto-sanitize by default
  (Angular's `[innerHTML]` binding sanitizes unless `bypassSecurityTrustHtml`
  is explicitly called) — confirm actual execution before flagging; a
  canary appearing as escaped text is not a finding.
- `document.write` calls fed only by static/build-time constants (not
  runtime URL state) are not exploitable — check the actual argument source.

## 6. CVSS Vector Construction
- Standard: `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (~6.1 Medium) — same
  UI:Required profile as reflected XSS since delivery still needs a victim
  to open a crafted URL.
- If the sink is reachable without any URL manipulation (e.g. a stored value
  that populates the URL automatically, like a saved search), treat it as
  closer to stored XSS severity (see `xss_stored_blackbox_SKILL.md` §6).

## 7. Remediation (by stack)
- Angular: never call `bypassSecurityTrustHtml`/`bypassSecurityTrustUrl`
  with user-controlled input — let Angular's built-in sanitizer run.
- Vue: avoid `v-html` with user-controlled data; use text interpolation
  (`{{ }}`) which escapes by default.
- React: avoid `dangerouslySetInnerHTML`; if HTML rendering is required,
  pass content through DOMPurify first.
- Vanilla JS: use `textContent`/`innerText` instead of `innerHTML` whenever
  the value isn't meant to contain markup; if it must, sanitize with
  DOMPurify before assignment.
