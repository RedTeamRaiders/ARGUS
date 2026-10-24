---
owasp_id: A08:2021
vuln_class: software_data_integrity
test_mode: whitebox
requires: [codebase_path]
primitive: integrity_bypass_confirmed
evidence_schema:
  required_proof: [integrity_check_bypassed, forged_artifact_accepted]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Software and Data Integrity Failures — White Box

## 1. Recon — Source-Level Integrity Review
- Grep for zip/archive extraction calls (`zipfile.extractall`,
  `unzipper`/`adm-zip` usage in Node) without a path-containment check.
- Grep for webhook handlers and verify whether a signature-check call
  precedes the business logic, or is missing/commented out.
- Grep JWT verification calls (shared with A07's review) specifically for
  the algorithm-pinning gap — cross-reference rather than re-doing the
  same grep twice across both categories.

## 2. Detection Methodology — Trace Pattern
```bash
grep -rn "extractall(\|\.extract(" --include="*.py" .
grep -rn "X-Hub-Signature\|verifySignature\|hmac\.compare" --include="*.js" --include="*.py" .
```
Flag `extractall()`/equivalent calls with no per-entry path validation, and
webhook handlers where the signature-verification call is absent, commented
out, or placed after the payload has already been acted upon.

## 3. Exploitation Path — Confirm in Runtime
Same dynamic confirmation as blackbox §3 — craft the zip-slip archive or
replay the webhook with a stripped signature — targeted at the exact
handler identified from source.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the missing
path-containment check or the absent/bypassed signature verification.

## 5. False-Positive Filtering
An `extractall()` call that's immediately followed by a recursive
path-containment sweep over the extracted directory (reject the whole
batch if any file landed outside the target dir) is TESTED_CLEAN even
though the initial call looks dangerous in isolation — read the full
function, not just the matched line.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `blackbox_SKILL.md` §6 in this
directory).

## 7. Remediation (by stack)
Same as blackbox §7, plus: add a semgrep rule flagging `extractall()`/
archive-extraction calls without an adjacent path-containment check, and
webhook handlers missing a signature-verification call before business
logic, to CI.
