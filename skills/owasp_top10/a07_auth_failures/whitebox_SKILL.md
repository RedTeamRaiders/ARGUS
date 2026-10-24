---
owasp_id: A07:2021
vuln_class: auth_failures
test_mode: whitebox
requires: [codebase_path]
primitive: auth_bypass_confirmed
evidence_schema:
  required_proof: [bypass_request_pair, session_or_identity_proof]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Identification and Authentication Failures — White Box

## 1. Recon — Source-Level Auth Review
- Read the session/JWT verification code directly: does `jwt.verify()`
  pin the expected algorithm, or trust the token's own `alg` header?
- Read the registration handler: does it spread `req.body` into the model
  create call, or explicitly allowlist fields?
- Read the login/reset handlers: do error paths for "user not found" and
  "wrong password" share the exact same code path and response, or branch
  separately (a branch is a strong enumeration signal even before dynamic
  testing)?

## 2. Detection Methodology — Trace Pattern
```bash
grep -rn "jwt\.verify(\|jwt\.decode(" --include="*.js" --include="*.py" . | grep -v "algorithms"
grep -rn "\.create(req\.body)\|\.create({.*\.\.\.req\.body" --include="*.js" .
```
Flag any `jwt.verify`/`jwt.decode` call without an explicit `algorithms`
allowlist, and any model-create call that spreads the full request body
without an intermediate allowlist/pick step.

## 3. Exploitation Path — Confirm in Runtime
Same dynamic confirmation as blackbox §3 (JWT forgery via `jwt_tool`, mass
assignment via direct POST), now targeted at the exact code paths
identified in step 2 — skip the broad probing, go straight to the known
gap.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the missing
algorithm pin or the unguarded mass-assignment call.

## 5. False-Positive Filtering
A `jwt.verify()` call without an explicit `algorithms` option may still be
safe if the library's default behavior for that version pins a single
algorithm — check the library version and its documented default before
flagging; note the version-dependent behavior either way.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `blackbox_SKILL.md` §6 in this
directory).

## 7. Remediation (by stack)
Same as blackbox §7, plus: add a semgrep rule flagging `jwt.verify`/`decode`
calls without an explicit `algorithms` array, and model-create calls
spreading `req.body` without a `pick`/allowlist step, to CI.
