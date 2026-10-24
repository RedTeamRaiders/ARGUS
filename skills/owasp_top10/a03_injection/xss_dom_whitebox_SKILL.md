---
owasp_id: A03:2021
vuln_class: xss_dom
test_mode: whitebox
requires: [codebase_path]
primitive: xss_dom_confirmed
evidence_schema:
  required_proof: [sink_identified, execution_confirmation]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: DOM-Based XSS — White Box

## 1. Recon — Taint-Source-to-Sink Mapping
- Grep the client-side bundle/source directly for dangerous sinks and trace
  backward to their source:
```bash
grep -rn "\.innerHTML\s*=\|document\.write(\|eval(\|bypassSecurityTrust\|v-html" --include="*.js" --include="*.ts" --include="*.vue" --include="*.jsx" src/
```
- For each hit, trace whether the assigned value originates from
  `location.hash`, `location.search`, `window.name`, `document.referrer`,
  or `postMessage` data — these are the classic DOM XSS taint sources.

## 2. Detection Methodology — Trace Pattern
A sink is a genuine candidate when:
1. The sink call (`innerHTML`, `eval`, etc.) receives a variable, not a
   literal.
2. That variable traces to one of the taint sources above without passing
   through a sanitizer or the framework's default-safe binding syntax.
3. No type/shape validation neutralizes it first (e.g. the hash value is
   parsed as an integer before use — not injectable as a string).

## 3. Exploitation Path — Confirm in Runtime
Once the sink and its exact taint source are identified from source, craft
the exact URL/fragment that reaches it and confirm with Playwright exactly
as in blackbox §3 — white box just skips the discovery/guessing step
because the sink is already known from source instead of inferred from
behavior.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the dangerous sink
call and the taint source it consumes — e.g.
`src/components/Search.vue:14 — v-html="route.query.q"`.

## 5. False-Positive Filtering
Same as blackbox §5, plus: a sink call wrapped in a project-local
`safeHtml()` helper that internally calls DOMPurify is not exploitable —
trace the helper's implementation, don't flag on the sink call's name alone.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `xss_dom_blackbox_SKILL.md` §6).

## 7. Remediation (by stack)
Same as blackbox §7, plus a whitebox-only addition: add an ESLint rule
(`eslint-plugin-no-unsanitized`) or equivalent static check to CI that flags
new `innerHTML`/`eval`/`bypassSecurityTrust*` call sites fed by non-literal
values.
