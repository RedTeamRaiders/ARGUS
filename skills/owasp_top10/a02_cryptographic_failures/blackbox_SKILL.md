---
owasp_id: A02:2021
vuln_class: crypto_failures
test_mode: blackbox
requires: []
primitive: crypto_weakness_confirmed
evidence_schema:
  required_proof: [weak_algorithm_observed, sensitive_data_exposure_sample]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Cryptographic Failures — Black Box

## 1. Recon — Attack Surface Mapping
- TLS configuration of every HTTPS endpoint (protocol versions, cipher
  suites, certificate validity).
- Password-reset tokens, session identifiers, API keys exposed in URLs
  (logged in server/proxy access logs, browser history, Referer headers).
- Any field-selection or export API that might leak hashed credentials
  (`?fields=password`) or full PII without redaction.
- Response headers and error pages for cryptographic version/library
  disclosure (`X-Powered-By`, stack traces mentioning crypto libraries).

## 2. Detection Methodology — Probe Sequence
1. Run `tool_wrappers/testssl.py` against every HTTPS endpoint — flags
   outdated protocols (TLS 1.0/1.1), weak ciphers, expired/self-signed
   certs, missing HSTS.
2. Check password-reset/email-verification token structure: is it
   predictable (sequential, timestamp-only, short)? Request several in
   quick succession and compare for a pattern.
3. Check cookie attributes on session tokens: missing `Secure`, missing
   `HttpOnly`, missing/weak `SameSite` — each is a distinct finding.
4. Probe for sensitive-field leakage via field-selection params or verbose
   API responses (`?fields=`, GraphQL introspection if present) returning
   password hashes, API secrets, or internal tokens.

## 3. Exploitation Path — Tool Invocation
```python
import tool_wrappers.testssl as testssl
result = await testssl.run(host, quick=True)
```
- If a weak/predictable token is suspected, request N tokens, decode/diff
  them (base64/hex decode, timestamp extraction) to demonstrate
  predictability — don't just assert it, show the pattern.
- If a password hash is leaked via an API response, identify the hash
  algorithm (length/format — MD5 32 hex chars, SHA-1 40, bcrypt `$2b$`
  prefix) as part of the evidence, not just "a hash was present."

## 4. Evidence Capture
`evidence_schema` requires `weak_algorithm_observed` (testssl output
showing the specific weak protocol/cipher, or the identified weak hash
format) AND `sensitive_data_exposure_sample` (the actual leaked
value/pattern — redacted appropriately per Part 6's evidence hygiene
before it lands in a report).

## 5. False-Positive Filtering
- An internal-only/non-production TLS endpoint intentionally using a
  self-signed cert for a dev environment isn't a finding if genuinely out
  of scope — confirm the target is the production/in-scope asset.
- A weak cipher offered by the server but never actually negotiated by any
  real client (verify via the server's cipher preference order, not just
  what's technically supported) is lower priority — note it but don't
  overstate exploitability without a downgrade-attack demonstration.

## 6. CVSS Vector Construction
- Outdated TLS protocol/weak cipher alone (no demonstrated MITM):
  `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` (~Medium) — `AC:H` since exploitation
  requires a network MITM position.
- Predictable password-reset token (account takeover path):
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H` (~High/Critical) — full account
  takeover potential.
- Leaked password hashes via API: `C:H` at minimum, higher if the hash
  algorithm is crackable quickly (MD5/SHA1 unsalted vs bcrypt).

## 7. Remediation (by stack)
- TLS: disable TLS 1.0/1.1 and weak ciphers at the load balancer/web server
  config (nginx `ssl_protocols`, Apache `SSLProtocol`); enforce HSTS.
- Tokens: use a CSPRNG (`secrets.token_urlsafe()` in Python,
  `crypto.randomBytes()` in Node) for reset/session tokens, never
  `Math.random()` or sequential IDs.
- Password hashing: bcrypt/argon2/scrypt with per-user salt, never
  MD5/SHA1/unsalted hashes; migrate existing weak hashes on next login.
- Cookies: `Secure; HttpOnly; SameSite=Strict` (or `Lax` if cross-site flows
  require it) on every session cookie.
