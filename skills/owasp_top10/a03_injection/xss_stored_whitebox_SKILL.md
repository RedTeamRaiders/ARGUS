---
owasp_id: A03:2021
vuln_class: xss_stored
test_mode: whitebox
requires: [codebase_path]
primitive: xss_stored_confirmed
evidence_schema:
  required_proof: [canary_persisted, execution_confirmation]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Stored XSS — White Box

## 1. Recon — Taint-Source-to-Sink Mapping
- Map every write path for user input (model/ORM `save()`/`create()` calls)
  to every corresponding read path that renders it. A field can be written
  safely but rendered unsafely in a *different* view — whitebox lets you
  find every renderer, not just the one the UI happens to show you.
- Pay special attention to admin/internal views that render the same field
  — these are often built later, hastily, without the same escaping
  discipline as the public-facing view.

## 2. Detection Methodology — Trace Pattern
1. Find the model field's write path — is input sanitized on write (bleach,
   sanitize-html, DOMPurify server-side) or stored raw?
2. Find every render path for that field — grep the field name across
   templates/components. Each render site is independently vulnerable or
   safe depending on its own escaping, regardless of what the write path did.
3. If a sanitizer is called on write, check its version against known
   bypasses (A06 territory) rather than assuming it's airtight — note the
   version and flag for the A06 pass if it's outdated.

## 3. Exploitation Path — Confirm in Runtime
Same canary → persist → payload → Playwright verification as blackbox §3,
narrowed to the specific render sites identified in step 2 above — test
every render site found via source, including ones not reachable from the
normal UI (internal admin views, export/print views, email-notification
templates that embed the field).

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` for both the write-path
sanitization gap (or absence) and each vulnerable render site found.

## 5. False-Positive Filtering
Same as blackbox §5, plus: a render site that looks unescaped in the
template but is actually passed through a wrapper helper function that
escapes before interpolation — trace the helper, don't assume from the
template syntax alone.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `xss_stored_blackbox_SKILL.md` §6)
— severity is driven by which viewer sees the payload, which whitebox
recon in step 1 identifies more completely than blackbox can.

## 7. Remediation (by stack)
Same as blackbox §7, plus: recommend centralizing output escaping in a
single rendering layer/component (a shared `<SafeText>` wrapper, a template
base macro) so future render sites inherit safety by default instead of
each one needing to remember to escape individually.
