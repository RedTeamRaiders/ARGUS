---
owasp_id: A10:2021
vuln_class: ssrf
test_mode: whitebox
requires: [codebase_path]
primitive: ssrf
evidence_schema:
  required_proof: [internal_fetch_confirmation, response_data_sample]
  min_tool_confirmations: 2
  oob_required: true
---

# Skill: Server-Side Request Forgery — White Box

## 1. Recon — Taint-Source-to-Sink Mapping
```bash
grep -rn "requests\.get(\|requests\.post(\|axios\.get(\|fetch(\|urllib\.request\|http\.get(" --include="*.py" --include="*.js" .
```
Trace each outbound-request call back to its URL argument's origin — is it
a hardcoded internal API call (not a finding) or built from user input
(candidate)?

## 2. Detection Methodology — Trace Pattern
A sink is genuine when: (1) the URL/hostname passed to the fetch call
originates from user input, (2) no allowlist/denylist validation of the
resolved destination happens first, (3) redirects aren't re-validated
(the library follows redirects by default with no destination re-check).

## 3. Exploitation Path — Confirm in Runtime
Same OOB-first confirmation as blackbox §2 — point the traced parameter at
a collaborator listener, then at internal targets/metadata endpoints —
now aimed precisely at the identified call site. White box also tells you
exactly which internal services the deployment network actually exposes
(from infra-as-code/docker-compose files), letting you target the probe
list precisely instead of guessing common ports.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the unvalidated
fetch call and its traced input source.

## 5. False-Positive Filtering
A fetch call that looks unvalidated at the call site may be preceded by a
shared `validateOutboundUrl()` helper applied earlier in the request
pipeline — trace the full call chain, not just the immediate fetch
invocation, before concluding validation is absent.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `blackbox_SKILL.md` §6 in this
directory).

## 7. Remediation (by stack)
Same as blackbox §7, plus: add a semgrep rule flagging outbound HTTP calls
(`requests.get`, `axios.get`, `fetch`) fed by non-literal arguments without
a preceding destination-validation call, to CI.
