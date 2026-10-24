---
owasp_id: A01:2021
vuln_class: access_control
test_mode: whitebox
requires: [codebase_path]
primitive: idor_confirmed
evidence_schema:
  required_proof: [cross_account_access_sample, authz_bypass_request_pair]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Broken Access Control — White Box

## 1. Recon — Entry Point Mapping
- Read every route definition file (`urls.py`, Express `router.*`, Spring
  `@RequestMapping`) and build the complete endpoint list, including
  internal/undocumented routes the UI never links to.
- For each endpoint, note: is there an auth-required decorator/middleware?
  Is there a role-required check? Is there an ownership check, or does it
  just trust the ID from the request?
- Identify whether authorization is centralized (one middleware/decorator
  pattern applied consistently) or per-endpoint (each handler rolls its
  own check) — per-endpoint patterns are far more likely to have a gap
  somewhere; prioritize auditing every instance if so.

## 2. Detection Methodology — Trace Pattern
A sink is a genuine candidate when a handler fetches a resource by an
ID taken from the request, and the ownership/role check is either:
(1) absent entirely, (2) present but checking the wrong field (role
instead of ownership, or vice versa), or (3) present on the read path but
missing on an adjacent write/delete path for the same resource.
```bash
grep -rn "get_object_or_404(\|findById(\|\.objects\.get(" --include="*.py" --include="*.js" . | grep -v "owner=\|user_id=\|userId:"
```

## 3. Exploitation Path — Confirm in Runtime
Code review identifies the exact missing/wrong check; confirm dynamically
exactly as in blackbox §2 — the horizontal/vertical/function-level request
pairs. White box advantage: you know in advance which endpoints lack the
check, so you test precisely rather than enumerating broadly.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the missing or
incorrect authorization check.

## 5. False-Positive Filtering
- A handler that looks unchecked at the route level may be covered by a
  global middleware registered earlier in the app's middleware chain —
  trace the full request pipeline, not just the handler function, before
  concluding a check is missing.
- An ownership check present but written against a stale/renamed field
  (leftover from a refactor) that happens to still always evaluate true
  for the test data — verify with genuinely distinct cross-account test
  data, not assumptions from reading the check's intent.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `blackbox_SKILL.md` §6 in this
directory).

## 7. Remediation (by stack)
Same as blackbox §7, plus: recommend refactoring per-endpoint authorization
checks into the centralized pattern identified as missing in step 1, with a
regression test asserting every new route under the resource's blueprint
inherits the check by default rather than opting in.
