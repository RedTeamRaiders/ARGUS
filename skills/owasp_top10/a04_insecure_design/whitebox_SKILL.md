---
owasp_id: A04:2021
vuln_class: insecure_design
test_mode: whitebox
requires: [codebase_path]
primitive: business_logic_bypass
evidence_schema:
  required_proof: [logic_bypass_request_pair, impact_demonstration]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Insecure Design — White Box

## 1. Recon — Design & Threat-Model Review
- Read the state machine (order status, workflow step enum) directly from
  the model/schema code — is every transition explicitly validated, or
  does the code only check the *current* request's fields without
  checking prior state?
- Find read-modify-write sequences without transactions: a balance check
  followed by a separate update call, with application code (not the DB)
  enforcing atomicity.
- Find any place the server trusts a client-submitted price/total instead
  of recomputing it from catalog/pricing data server-side.

## 2. Detection Methodology — Trace Pattern
```bash
grep -rn "quantity\s*=\|price\s*=\|amount\s*=" --include="*.py" --include="*.js" . | grep -i "request\|req\.\|body\."
```
Flag any handler that uses a client-submitted price/total/discount value
directly in a calculation rather than looking it up server-side. Flag any
multi-step workflow whose later-step handler doesn't verify prior-step
completion via a server-side status field.

## 3. Exploitation Path — Confirm in Runtime
Same dynamic demonstration as blackbox §3, now targeted precisely at the
identified gap — craft the exact request sequence or concurrent-request
pattern that exploits the specific non-atomic operation or missing state
check found in source.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the missing
state-transition check or non-atomic operation.

## 5. False-Positive Filtering
A read-modify-write that looks non-atomic in application code may actually
run inside a DB-level transaction wrapper applied at a higher layer
(an ORM `atomic()` decorator, a middleware-level transaction) — trace the
full call stack before concluding it's genuinely race-prone.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `blackbox_SKILL.md` §6 in this
directory).

## 7. Remediation (by stack)
Same as blackbox §7, plus: recommend a design-level fix (introducing an
explicit state machine library, or a server-side pricing/recalculation
service) rather than a point patch, since insecure design findings
typically recur across multiple endpoints sharing the same flawed pattern.
