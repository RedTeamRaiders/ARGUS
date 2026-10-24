---
owasp_id: A03:2021
vuln_class: xss_stored
test_mode: blackbox
requires: []
primitive: xss_stored_confirmed
evidence_schema:
  required_proof: [canary_persisted, execution_confirmation]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Stored XSS — Black Box

## 1. Recon — Attack Surface Mapping
- Prioritize crown-jewel viewers first: anything an admin/moderator will
  view (comment moderation queue, support ticket viewer, admin user list,
  review display) outranks a field only the submitter ever sees again.
- Candidate surfaces: comment fields, display names, profile bios, product
  reviews, file metadata (filename, EXIF, SVG `<title>`), support ticket
  subject/body.
- Note every surface that accepts input via the UI vs via direct API POST
  — client-side validation (character limits, HTML stripping in the form)
  is often absent server-side, so test the raw API call too, not just the
  rendered form.

## 2. Detection Methodology — Canary → Persistence → Reflection-on-View
1. Submit a unique canary through the surface.
2. Confirm it persisted: re-fetch the record (API GET, or re-render the
   page) and check the canary survived storage unmodified or whether it was
   HTML-encoded on the way back out (encoded = likely safe).
3. If unmodified, the surface is viable. Move to payload selection using the
   same context-detection logic as reflected XSS (§2 of the reflected
   skill) applied to the *view* page, not the submission response.
4. Critically: test the surface via a direct API POST even if the UI form
   has stricter client-side validation — `POST /api/Feedbacks/` bypassing
   Angular/React validation is a common gap this class specifically targets.

## 3. Exploitation Path — Payload + Multi-Viewer Verification
- Inject the context-appropriate payload (same families as reflected XSS §3).
- Verify execution in the submitter's own view first (Playwright dialog
  confirmation), then — if in scope and a test/admin account exists — verify
  it also fires in the higher-privilege viewer's context (moderation queue,
  admin panel). The second verification is what elevates this from
  "self-XSS stored" to a real stored XSS with blast radius.
- Use `tool_wrappers/dalfox.py` for broad surface sweeping before the manual
  Playwright confirmation on the specific surface that looks promising.

## 4. Evidence Capture
`evidence_schema` requires `canary_persisted` (proof the canary survived
storage unescaped — a GET response or page render showing it raw) AND
`execution_confirmation` (Playwright dialog/event trigger on view). Note
which viewer context execution was confirmed in — submitter-only vs
higher-privilege — this directly drives severity in §6.

## 5. False-Positive Filtering
- HTML-encoding on output (`&lt;script&gt;`) means the storage layer is
  fine but render layer encodes correctly — TESTED_CLEAN, not a finding.
- A payload that persists but only fires when the submitter's own browser
  re-renders it a specific way (e.g. requires a plugin, non-default
  browser setting) isn't exploitable against a normal victim — note as a
  near-miss, don't report at full severity.
- Markdown/rich-text fields with an allowlist sanitizer: test known bypass
  patterns for the specific library in use (check A06 for version-specific
  CVEs) before concluding clean — a generic payload failing doesn't mean
  the sanitizer is unbypassable, only that the generic payload didn't work.

## 6. CVSS Vector Construction
- Stored XSS visible only to the submitter: `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N` (~5.4 Medium) — low blast radius.
- Stored XSS visible to other regular users (public comment/review): `S:C/C:L/I:L`, often High depending on session-theft impact — `UI:N` since victims just need to view the page.
- Stored XSS visible to admin/moderator (admin panel, moderation queue):
  treat as the highest tier — `PR:N/UI:N/S:C/C:H/I:H` (~8-9 Critical/High),
  since it chains directly to full account/session compromise of a
  privileged user.

## 7. Remediation (by stack)
- Same encode-on-output guidance as reflected XSS §7 — the fix is identical
  regardless of persistence; the storage layer is not where XSS is
  prevented, the render layer is.
- For rich-text fields that genuinely need some HTML: use a maintained
  allowlist sanitizer (DOMPurify client-side, `bleach`/`sanitize-html` with
  the latest version server-side) and re-sanitize on every render, not just
  on write — a sanitizer bypass later shouldn't be permanently embedded in
  stored data.
