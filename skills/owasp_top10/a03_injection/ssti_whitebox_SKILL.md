---
owasp_id: A03:2021
vuln_class: ssti
test_mode: whitebox
requires: [codebase_path]
primitive: ssti_rce_confirmed
evidence_schema:
  required_proof: [math_eval_confirmation, command_output_sample]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Server-Side Template Injection — White Box

## 1. Recon — Taint-Source-to-Sink Mapping
```bash
grep -rn "render_template_string(\|Template(\|pug\.render(\|\.compile(\|eval(" --include="*.py" --include="*.js" .
```
Any call that compiles/renders a template from a **variable** (not a fixed
file path) is a candidate — trace that variable back to see if any part of
it is user-controlled, even if most of the string is a fixed wrapper with
one user-controlled segment concatenated in.

## 2. Detection Methodology — Trace Pattern
A sink is genuine when the template source string itself (not just the
context data passed into an already-fixed template) contains
user-controlled content. Rendering a fixed `.html`/`.pug` file with
user-supplied context variables is normal and safe — that's not this class.
Building the template string dynamically from user input is the actual bug.

## 3. Exploitation Path — Confirm in Runtime
Same math-eval → engine fingerprint → RCE payload sequence as blackbox §2–3,
now aimed precisely at the traced sink. White box also tells you the exact
template engine from the `import`/`require` statement, skipping the
engine-fingerprinting probes entirely — go straight to the engine-specific
RCE payload.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the dynamic-template
construction call.

## 5. False-Positive Filtering
A dynamic-looking render call fed by a value selected from a fixed enum of
template names (a "theme" selector choosing between 3 known `.pug` files) is
not injectable — the user controls *which* fixed template renders, not the
template's source content. Verify the actual string passed to `render`/`compile`
traces to free-text input, not a constrained selector.

## 6. CVSS Vector Construction
Identical scoring to blackbox (see `ssti_blackbox_SKILL.md` §6).

## 7. Remediation (by stack)
Same as blackbox §7, plus: add a semgrep rule flagging
`render_template_string`/dynamic `pug.render`/`Template(userInput)` call
patterns in CI.
