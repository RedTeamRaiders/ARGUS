---
owasp_id: A02:2021
vuln_class: crypto_failures
test_mode: whitebox
requires: [codebase_path]
primitive: crypto_weakness_confirmed
evidence_schema:
  required_proof: [weak_algorithm_observed, sensitive_data_exposure_sample]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Cryptographic Failures — White Box

## 1. Recon — Source-Level Crypto Inventory
```bash
grep -rn "md5(\|sha1(\|Math\.random(\|DES\|ECB\|hashlib\.md5\|hashlib\.sha1" --include="*.py" --include="*.js" --include="*.java" .
```
Catalog every hashing/encryption call site, the algorithm used, and whether
it's used for passwords, tokens, or data-at-rest encryption — the fix
differs by purpose.

## 2. Detection Methodology — Trace Pattern
Flag: password hashing using a fast general-purpose hash (MD5/SHA1/SHA256
without a KDF) instead of bcrypt/argon2/scrypt; token generation using
`Math.random()`/`random.random()` (non-CSPRNG) instead of
`secrets`/`crypto.randomBytes`; hardcoded encryption keys/IVs; ECB mode
block ciphers.

## 3. Exploitation Path — Confirm in Runtime
Same dynamic confirmation as blackbox §3 — demonstrate token predictability
or extract a password hash via a live request — but now the exact source
of the weakness is already known, so craft the dynamic PoC directly against
the identified code path rather than probing broadly.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the weak
algorithm/CSPRNG-absence call site.

## 5. False-Positive Filtering
A `Math.random()` call used only for non-security randomness (a UI
animation delay, a cosmetic shuffle) is not a finding — confirm the call
site actually feeds a security-relevant value (token, key, nonce) before
flagging.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `blackbox_SKILL.md` §6 in this
directory).

## 7. Remediation (by stack)
Same as blackbox §7, plus: add a semgrep/bandit rule to CI flagging new
`md5`/`sha1`/`Math.random` usage in security-sensitive contexts
(password/token/key generation) before merge.
