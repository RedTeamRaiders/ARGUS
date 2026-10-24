---
owasp_id: A07:2021
vuln_class: auth_failures
test_mode: blackbox
requires: []
primitive: auth_bypass_confirmed
evidence_schema:
  required_proof: [bypass_request_pair, session_or_identity_proof]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Identification and Authentication Failures — Black Box

## 1. Recon — Attack Surface Mapping
- Login, registration, password-reset, 2FA/MFA enrollment and challenge
  endpoints.
- Session mechanism: cookie-based, JWT, or custom token — identify which,
  since the attack surface differs (session fixation vs JWT algorithm
  attacks).
- Registration flow: does it accept privilege-affecting fields (`role`,
  `isAdmin`, `verified`) in the body?

## 2. Detection Methodology — Probe Sequence
1. **Credential stuffing surface**: is there a lockout/rate-limit after N
   failed attempts? Test with a known-bad password repeated — if unlimited
   attempts succeed without lockout, that's a finding on its own.
2. **Username enumeration**: compare error messages/timing between
   "user doesn't exist" and "wrong password" responses on login AND
   password-reset — a measurable difference enables account enumeration.
3. **Session fixation/weak session ID**: can a pre-auth session ID be
   reused post-auth without rotation? Decode the session token/JWT —
   is it signed properly, does it expire, is `alg: none` or a weak secret
   accepted (see JWT-specific checks below)?
4. **JWT-specific**: if sessions are JWT-based, test `alg: none`,
   RS256→HS256 confusion (using the public key as an HMAC secret), and
   missing expiry validation using `tool_wrappers/jwt_tool.py`.
5. **Mass assignment at registration**: POST directly to the registration
   API with an extra `role: "admin"`/`isAdmin: true` field not exposed in
   the UI form.

## 3. Exploitation Path — Tool Invocation
```python
import tool_wrappers.jwt_tool as jwt_tool
result = await jwt_tool.run(target_token, mode="exploit")  # alg confusion, none-alg, crack
```
- For username enumeration, script a timing/error-diff comparison across
  a known-valid and several known-invalid identifiers via
  `tool_wrappers/http_request.py`.
- For mass assignment, send the registration POST with the extra
  privilege field and then verify the resulting account's actual
  privilege level via a follow-up authenticated request.

## 4. Evidence Capture
`evidence_schema` requires `bypass_request_pair` (the exact request that
achieved the bypass, paired with a baseline showing normal behavior) AND
`session_or_identity_proof` (confirmation of the resulting elevated
identity/session — e.g. a subsequent authenticated request showing admin
access, or a forged JWT accepted by the server).

## 5. False-Positive Filtering
- A timing difference under 50-100ms between enumeration responses may be
  network jitter, not a real oracle — repeat the measurement multiple
  times and use the median, not a single sample.
- A JWT `alg: none` payload that's rejected (401) confirms the server
  validates algorithm correctly — TESTED_CLEAN, not a near-miss worth
  escalating further without a different attack angle.
- Mass assignment fields that are accepted by the API but silently ignored
  by the business logic layer (the field exists in the schema but a
  separate authorization step still gates privilege) — verify the
  resulting account's ACTUAL privilege, not just that the field was
  accepted in the response echo.

## 6. CVSS Vector Construction
- Full auth bypass (JWT forgery, mass-assignment-to-admin):
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H` at minimum (~9+ Critical).
- Username enumeration alone (no bypass, just identity confirmation):
  `C:L` only (~Low/Medium) — a building block, not full compromise by
  itself; note it as a contributor if chained with credential stuffing.
- Missing lockout/rate-limiting on login: Medium on its own, escalates if
  combined with a leaked credential list (see Part 4 chain detection).

## 7. Remediation (by stack)
- JWT: explicitly specify and enforce the expected algorithm on verify
  (`jwt.verify(token, secret, {algorithms: ['HS256']})`), never accept
  whatever `alg` the token claims.
- Rate limiting: implement account lockout/exponential backoff after N
  failed attempts, scoped per-account and per-IP.
- Enumeration: return identical error messages and response timing for
  "user not found" and "wrong password" on both login and password-reset.
- Mass assignment: explicit allowlist of fields accepted at registration
  (never spread `req.body` directly into a model create call); privilege
  fields set only by a separate admin-only endpoint.
