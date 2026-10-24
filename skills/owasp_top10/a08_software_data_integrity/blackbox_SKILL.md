---
owasp_id: A08:2021
vuln_class: software_data_integrity
test_mode: blackbox
requires: []
primitive: integrity_bypass_confirmed
evidence_schema:
  required_proof: [integrity_check_bypassed, forged_artifact_accepted]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Software and Data Integrity Failures — Black Box

## 1. Recon — Attack Surface Mapping
- JWT/signed-token usage anywhere (session, API auth, password-reset
  links, pre-signed upload URLs) — signature verification failures live
  here, not under A07, per this pass's categorization (keep JWT findings
  under A08:2021).
- File-upload features that accept archives (ZIP/TAR) — path-traversal
  write via crafted archive entries ("zip slip").
- Auto-update/plugin-loading mechanisms, CI/CD webhook endpoints, and any
  deserialization of client-supplied data into server-side objects.

## 2. Detection Methodology — Probe Sequence
1. **JWT signature bypass**: `alg: none` (strip signature entirely), and
   RS256→HS256 confusion (use the server's own public key, if exposed, as
   an HMAC secret to forge a validly-signed-looking token) — same probes
   as A07's JWT checks, but the *finding* for a bypassed signature
   verification is logged here under A08.
2. **Zip slip**: upload a ZIP containing an entry with a path-traversal
   name (`../../etc/cron.d/evil`, or a web-root-relative path like
   `../../public/shell.php`) and check whether extraction honors the
   traversal.
3. **Unsigned/unverified update or webhook payloads**: if a webhook
   endpoint claims to verify a signature header (`X-Hub-Signature`), test
   with a missing or malformed signature — does it still process the
   payload?

## 3. Exploitation Path — Tool Invocation
```python
import tool_wrappers.jwt_tool as jwt_tool
result = await jwt_tool.run(target_token, mode="exploit")
```
- For zip slip, craft the archive manually (standard zip tooling with a
  relative-path entry name) and upload via the discovered upload endpoint;
  confirm by requesting the resulting path to verify the file landed
  outside the intended directory.
- For webhook signature bypass, replay a captured webhook payload with the
  signature header stripped/altered via `tool_wrappers/http_request.py`.

## 4. Evidence Capture
`evidence_schema` requires `integrity_check_bypassed` (the exact mechanism
defeated — alg confusion, missing signature check, path-traversal
extraction) AND `forged_artifact_accepted` (proof the server accepted the
forged/unsigned artifact as legitimate — a session granted from a forged
JWT, a file written outside the intended directory, a webhook action
executed despite a bad signature).

## 5. False-Positive Filtering
- A JWT library that rejects `alg: none` and algorithm-confusion attempts
  correctly is TESTED_CLEAN — don't force a finding if both probes fail
  cleanly.
- A zip-upload feature that extracts into a sandboxed, already-isolated
  temp directory with no further trust placed in extracted paths (verified
  by checking where the extracted content is actually served from) may
  not be exploitable even if traversal entries are technically written —
  confirm actual impact (a file reachable/executable outside the sandbox).

## 6. CVSS Vector Construction
- Forged JWT granting arbitrary identity/admin session:
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H` at minimum (~9+ Critical).
- Zip slip achieving arbitrary file write in a web-servable directory
  (webshell path): escalate to RCE-tier scoring once a webshell is
  confirmed reachable (`C:H/I:H/A:H`, 10.0) — see Part 4 for the
  `arbitrary_file_write` + `local_file_inclusion` → `webshell_rce` chain.
- Webhook signature bypass triggering a real action: scope impact to what
  the webhook actually controls (deployment trigger = Critical, a
  notification-only webhook = Low).

## 7. Remediation (by stack)
- JWT: pin the expected algorithm explicitly on verify (see A07 §7); never
  derive the HMAC secret from a value that's also published as a public
  key.
- Zip extraction: validate every archive entry's resolved path stays
  within the intended extraction directory before writing
  (`os.path.realpath` + prefix check, or a library with built-in zip-slip
  protection) — reject the entire archive on any entry that fails.
- Webhooks: verify the signature (HMAC over the raw body with a shared
  secret) BEFORE parsing/acting on the payload, using a constant-time
  comparison (`hmac.compare_digest`, not `==`).
