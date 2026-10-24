---
owasp_id: A01:2021
vuln_class: access_control
test_mode: blackbox
requires: []
primitive: idor_confirmed
evidence_schema:
  required_proof: [cross_account_access_sample, authz_bypass_request_pair]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Broken Access Control — Black Box

## 1. Recon — Attack Surface Mapping
- Every endpoint that takes an object ID (numeric or UUID) in the URL,
  body, or query: `/api/users/<id>`, `/api/orders/<id>`,
  `/api/documents/<id>/download`.
- Every admin/privileged-only feature reachable in the UI or discovered via
  directory enum/JS bundle analysis (`linkfinder` output) — test whether it
  checks role server-side, not just whether the UI hides the link.
- Create two test accounts of different privilege levels where the
  engagement allows it — horizontal (user A vs user B) and vertical
  (regular user vs admin) testing both require a second identity.

## 2. Detection Methodology — Probe Sequence
1. **Horizontal**: as user A, request user B's resource by ID
   (`GET /api/orders/<B's_order_id>` while authenticated as A). Any
   non-403/401 response with B's data is a confirmed IDOR.
2. **Vertical**: as a regular user, request an admin-only endpoint
   directly (bypassing UI hiding) — `GET /api/admin/users`. A 200 with
   data is confirmed broken access control.
3. **Function-level**: test state-changing verbs (PUT/PATCH/DELETE) on
   resources owned by another user, not just GET — read-access IDOR and
   write-access IDOR are different severities (see §6).
4. **Unauthenticated**: strip the auth header/cookie entirely and retry key
   endpoints — some routes check role but not authentication at all.

## 3. Exploitation Path — Tool Invocation
- Use `arjun` output (already collected) to find every parameter name that
  looks like an object reference (`id`, `uid`, `account_id`, `order_id`).
- Script the cross-account request pair manually via
  `tool_wrappers/http_request.py` — same request, swap only the ID and the
  auth token, diff the responses.
- For sequential/numeric IDs, test ID enumeration (±1 from a known ID) to
  assess blast radius (how many other users' records are reachable), not
  just whether one worked.

## 4. Evidence Capture
`evidence_schema` requires `cross_account_access_sample` (the actual data
belonging to the other account, returned to the wrong session) AND
`authz_bypass_request_pair` (the exact two HTTP requests — as the
legitimate owner and as the attacker — showing identical success with
different identities).

## 5. False-Positive Filtering
- Globally public resources (a product catalog, a public profile page) are
  not IDOR even though they're ID-addressable — confirm the resource is
  supposed to be private before flagging.
- A resource returning a generic "not found" for both in-scope and
  out-of-scope IDs (indistinguishable 404s) is NOT vulnerable even if a 404
  technically differs from a 403 — the information disclosure risk there is
  separate and much lower severity; don't conflate with full IDOR.
- Session/cookie reuse artifacts: confirm you're actually authenticated as
  the intended lower-privilege account (check `whoami`-equivalent response)
  before concluding a privilege check failed.

## 6. CVSS Vector Construction
- Read-only horizontal IDOR (view another user's non-sensitive data):
  `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (~5-6 Medium).
- Read-only IDOR on sensitive PII (financial, health, auth tokens):
  raise `C:H` (~7-8 High).
- Write/delete IDOR (modify or delete another user's resource):
  `C:L/I:H/A:L` or higher depending on resource criticality (~8+ High).
- Vertical escalation to admin functionality: `PR:L/S:C/C:H/I:H` at minimum
  (~9+ Critical) since it's a full privilege boundary break.

## 7. Remediation (by stack)
- Centralize an authorization check (middleware/decorator) that validates
  resource ownership against the authenticated session on every
  object-fetching route — never rely on the ID being "hard to guess."
- Django: use `get_object_or_404(Model, pk=id, owner=request.user)` pattern,
  not `get_object_or_404(Model, pk=id)` followed by a manual check that's
  easy to forget on a new endpoint.
- Express/Node: a shared `requireOwnership(resourceType)` middleware applied
  consistently, not a per-route inline check.
- General: prefer non-sequential IDs (UUIDv4) as defense in depth, but
  treat it as a mitigation, never a substitute for the authorization check
  itself.
