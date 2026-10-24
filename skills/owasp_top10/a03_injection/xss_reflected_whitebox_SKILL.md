---
owasp_id: A03:2021
vuln_class: xss_reflected
test_mode: whitebox
requires: [codebase_path]
primitive: xss_reflected_confirmed
evidence_schema:
  required_proof: [canary_reflection, execution_confirmation]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Reflected XSS — White Box

## 1. Recon — Taint-Source-to-Sink Mapping
- Trace every route handler that reads a query/body param and writes it
  directly into a response: `res.send(` / `res.render(` with string
  concatenation, `return HttpResponse(f"...")`, raw template interpolation
  without the engine's escape filter.
- Grep for the project's templating engine and check whether escaping is the
  default or opt-in: Jinja2/Handlebars/React default-escape; `|safe`,
  `{{{ }}}`, `dangerouslySetInnerHTML`, `v-html` are the explicit opt-outs —
  grep for those opt-out calls first, they're the highest-yield targets.

## 2. Detection Methodology — Trace Pattern
A sink is a genuine candidate when:
1. User input flows from `request.args`/`req.query`/`req.body` to an
   output-writing call.
2. No escaping/encoding function sits between source and sink.
3. The output-writing call is one of the explicit raw/unsafe variants above,
   OR a hand-rolled string response (`Content-Type: text/html` manually set
   with f-string body).
```bash
grep -rn "dangerouslySetInnerHTML\|v-html\|\[innerHTML\]\||safe\|{{{" --include="*.js" --include="*.jsx" --include="*.py" --include="*.html" .
```

## 3. Exploitation Path — Confirm in Runtime
Code review narrows the candidate parameter; confirm it exactly like
blackbox (§3 of `xss_reflected_blackbox_SKILL.md`) — canary → context
analysis → payload → Playwright execution check. White box advantage: you
already know the exact escaping gap from source, so you can skip the
context-guessing step and go straight to the right payload family.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus the mandatory `file:line` of the
unsafe sink per the white box reporting standard — e.g.
`templates/search.html:42 — {{{ query }}}` or
`routes/search.js:18 — res.send(\`<h1>${req.query.q}</h1>\`)`.

## 5. False-Positive Filtering
- A raw-looking sink that's actually inside a sandboxed template partial the
  app never renders with untrusted input (e.g. an internal admin-only debug
  view gated behind a separate auth layer) — verify the route's authz
  middleware before flagging; log TESTED_CLEAN with the auth gate noted if
  genuinely inaccessible.
- A `|safe`/`dangerouslySetInnerHTML` call fed by a value that passes
  through a sanitizer library (DOMPurify, bleach) upstream is not
  exploitable unless the sanitizer itself has a known bypass — check A06
  for that angle instead of flagging here.

## 6. CVSS Vector Construction
Identical scoring to blackbox (see `xss_reflected_blackbox_SKILL.md` §6).

## 7. Remediation (by stack)
Same as blackbox §7, plus a whitebox-only addition: add a lint rule
(`eslint-plugin-react` `no-danger`, a semgrep rule for `|safe`/`{{{`) to CI
so new unsafe sinks fail the build rather than reaching production.
