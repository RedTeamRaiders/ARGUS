---
owasp_id: A03:2021
vuln_class: xss_reflected
test_mode: blackbox
requires: []
primitive: xss_reflected_confirmed
evidence_schema:
  required_proof: [canary_reflection, execution_confirmation]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Reflected XSS — Black Box

## 1. Recon — Attack Surface Mapping
- Every GET/POST param that echoes back into the response: search boxes,
  error pages (`?msg=`), redirect params, sort/filter params that render
  as "Showing results for: X".
- Pull candidates from `context.endpoints` (already crawled) rather than
  re-fuzzing — prioritize params whose value appears unchanged in the raw
  HTML response, not just in a JSON API body (that's a different risk
  profile — see `xss_dom` if it's client-rendered).

## 2. Detection Methodology — Canary Probe Sequence
1. Inject a unique, inert canary string (`argus_xss_<random>`) into each
   candidate param — never the real payload first.
2. Grep the response for the canary verbatim. No reflection → not viable,
   move on.
3. Reflection found → inspect the exact surrounding bytes to determine
   context: raw HTML body, HTML attribute value, `<script>` block, or CSS.
   This determines the payload family in step 3 — guessing a `<script>`
   payload into an attribute context wastes a request and looks noisy.

## 3. Exploitation Path — Context-Appropriate Payload + Verification
- HTML-body context: `<img src=x onerror=alert(1)>` or `<iframe src="javascript:alert(1)">`.
- Attribute context (e.g. inside `value="..."`): break out first —
  `"><script>alert(1)</script>` or `" onmouseover=alert(1) x="`.
- `<script>` block context: no new tags needed — close the string literal
  and inject directly: `';alert(1);//`.
- Verify execution with Playwright (never assume from reflection alone):
  ```python
  from tool_wrappers.argus_crawler.monitor import ExecutionMonitor
  async with ExecutionMonitor(page) as monitor:
      await injector.inject(surface, payload)
      events = await monitor.check_execution(wait_ms=1500)
  # monitor.confirmed_xss == True is the second tool confirmation
  ```
- If a WAF is fingerprinted (from `wafw00f` in active recon), start from
  `xss_waf_bypass.json` payload knowledge before iterating manually.

## 4. Evidence Capture
`evidence_schema` requires: `canary_reflection` (the raw response snippet
showing the unique canary echoed back unescaped) AND `execution_confirmation`
(Playwright's `monitor.confirmed_xss` dialog/event trigger, captured via
`EvidenceCollector`). Reflection alone is not sufficient — this vuln class
is `confirmed=True` only once real execution fires in a real browser
context.

## 5. False-Positive Filtering
- Framework auto-escaping: Angular/React/Vue escape interpolated text by
  default — a reflected canary inside `{{ }}` or `{}` bindings that renders
  as literal text (not executed) is NOT exploitable; confirm actual script
  execution, not just visual presence of the payload.
- WAF-mangled output: a reflected canary with characters silently stripped
  (`<script>` → `script`) means the WAF normalized the payload — retry with
  an encoding/case variant before concluding clean.
- Self-XSS: if the payload only fires in the attacker's own session with no
  way to deliver the URL to a victim (e.g. requires a POST-only form with no
  CSRF-exploitable GET equivalent), downgrade impact — note the limitation,
  don't inflate severity.

## 6. CVSS Vector Construction
- Reflected XSS requiring a victim to click a crafted link: `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (~6.1 Medium).
- Reflected XSS reachable without user interaction (e.g. reflected into an
  auto-loaded resource): raise `UI` consideration accordingly, but this is
  rare for reflected (vs stored).
- Scope `S:C` (changed) when the XSS executes in the victim's authenticated
  session rather than the attacker's own.

## 7. Remediation (by stack)
- React/Vue/Angular: never use `dangerouslySetInnerHTML`/`v-html`/`[innerHTML]`
  with unsanitized user input — rely on default text interpolation, which
  auto-escapes.
- Server-rendered templates (Jinja2, EJS, Pug): use auto-escaping template
  syntax (`{{ }}` in Jinja2, not `{{{ }}}`/`|safe`); same for EJS `<%= %>`
  not `<%- %>`.
- All stacks: set a restrictive Content-Security-Policy (`script-src 'self'`,
  no `unsafe-inline`) as defense in depth, not as the primary fix.
