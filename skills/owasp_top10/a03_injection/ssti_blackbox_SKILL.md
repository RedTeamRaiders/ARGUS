---
owasp_id: A03:2021
vuln_class: ssti
test_mode: blackbox
requires: []
primitive: ssti_rce_confirmed
evidence_schema:
  required_proof: [math_eval_confirmation, command_output_sample]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Server-Side Template Injection — Black Box

## 1. Recon — Attack Surface Mapping
- Target any field whose value appears to be "processed" rather than
  simply displayed: a username that affects a greeting ("Welcome, X"),
  a report-title field, an email-template preview, a PDF-generation
  description field — anywhere text gets dynamically composed server-side.
- Note the tech stack signal from `httpx`/response headers — Jinja2/Twig
  (Python/PHP), Pug/Handlebars/EJS (Node), Freemarker/Velocity (Java) each
  have distinct polyglot probes.

## 2. Detection Methodology — Polyglot Probe + Engine Fingerprint
1. Send a math-evaluation polyglot that's inert text in most engines but
   evaluates in a template context: `${7*7}`, `#{7*7}`, `{{7*7}}`, `<%= 7*7 %>`.
2. If any variant renders as `49` instead of the literal probe string,
   you've confirmed template evaluation and fingerprinted the engine family
   by which syntax fired.
3. Narrow to the exact engine with engine-specific probes:
   - Jinja2: `{{7*'7'}}` → `7777777` (Python), `49` (else) disambiguates
     Jinja2 vs Twig.
   - Pug (Juice-Shop-style eval-based rendering): `#{process.mainModule}` —
     avoid `<` entirely, since many WAFs/sanitizers key on it.

## 3. Exploitation Path — RCE Payload per Engine
Once engine is confirmed, escalate from math-eval to code execution:
- Jinja2 (Python): `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`
- Pug (Node, `eval`-based): `#{process.mainModule.require('child_process').execSync('id').toString()}`
- Freemarker (Java): `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- Always confirm with a benign, non-destructive command (`id`, `whoami`)
  first — this class goes straight to RCE, treat it with the same
  conservatism as command injection.

## 4. Evidence Capture
`evidence_schema` requires `math_eval_confirmation` (the response showing
`49` or equivalent for the specific engine probe) AND `command_output_sample`
(real OS command output via the engine-specific RCE payload). The math-eval
step is not optional even if RCE succeeds directly — it's the artifact that
proves *which* engine and *why* the payload worked, needed for remediation.

## 5. False-Positive Filtering
- A literal `{{...}}` reflected unchanged (not evaluated) means the field is
  passed as data, not re-parsed as a template — not injectable, move on.
- Client-side template frameworks (Angular's `{{ }}` interpolation,
  Vue/Handlebars client-side) are NOT server-side template injection — if
  the math-eval only resolves in the browser DOM (not in the raw HTTP
  response), that's `xss_dom`, a different vuln class, not SSTI.
- Sanitizer bypass patterns (e.g. avoiding `<` via `#{...}` syntax) can
  still be blocked by a stricter allowlist — if the probe is stripped
  entirely rather than reflected literally, that's a sanitizer actively
  rejecting the input, worth noting but not a finding yet.

## 6. CVSS Vector Construction
SSTI that achieves RCE is scored identically to command injection RCE:
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0 Critical) when unauthenticated
and the command executes with the web server's privileges. If only
math-eval is confirmed but RCE payloads are blocked by an incomplete
sandboxing layer (as with `notevil`/`safeEval`-style guarded eval), score
as data/availability impact only until RCE is actually demonstrated —
don't claim Critical on math-eval alone.

## 7. Remediation (by stack)
- Jinja2/Python: never call `render_template_string()` with user input;
  use `render_template()` with a fixed template file and pass user data as
  context variables only.
- Pug/Node: never construct template source strings from user input
  (`pug.render(userControlledString)`); if user content must appear in a
  rendered page, pass it as locals to a fixed `.pug` file.
- Freemarker/Java: disable `Execute`/`ObjectConstructor` built-ins in the
  configuration (`TemplateClassResolver`), and never use
  `Configuration.getTemplate(userInput)`.
- General: treat "the user's text becomes part of the template source" as
  the actual vulnerability class, not any specific syntax — the fix is
  always separating template structure from user data.
