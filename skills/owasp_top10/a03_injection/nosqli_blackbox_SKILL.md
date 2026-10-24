---
owasp_id: A03:2021
vuln_class: nosqli
test_mode: blackbox
requires: []
primitive: nosqli_read
evidence_schema:
  required_proof: [extracted_data_sample, boolean_or_timing_diff]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: NoSQL Injection — Black Box

## 1. Recon — Attack Surface Mapping
- Target any endpoint whose backend is fingerprinted as MongoDB/CouchDB
  (from `httpx` tech detection, error messages mentioning `$where`/`BSON`,
  or a `mongo`/`mongoose` signal in `context.tech_stack`).
- Prioritize endpoints accepting structured JSON bodies (PATCH/PUT with a
  filter-like `id` or query object) over simple string params — NoSQLi
  usually requires injecting an object, not a string, which JSON-body
  endpoints make trivial.

## 2. Detection Methodology — Probe Sequence
1. Operator injection via JSON body: replace a scalar value with a MongoDB
   query operator object — `{"id": {"$ne": null}}`, `{"id": {"$gt": ""}}` —
   and compare the response against the baseline scalar request.
2. Operator injection via URL-encoded form/GET params (when the backend
   parses bracket notation into nested objects, common in Express +
   `qs`/`body-parser`): `?id[$ne]=1` or `?id[$regex]=.*`.
3. Timing-based blind confirmation: `$where` clauses that accept arbitrary
   JS are the NoSQL equivalent of SQL time-based blind — `this.sleep(5000)`
   or a deliberately expensive regex comparison, measured against baseline
   latency.

## 3. Exploitation Path — Data Extraction
- Bulk-match operators to widen result sets beyond the intended single
  record: `{"$regex": ".*"}` on an `id`/`email` field in a PATCH/bulk-update
  endpoint returns/affects more rows than intended — the row count delta
  itself is the proof.
- `$where` always-true conditions to exfiltrate beyond the caller's own
  records: `' || true || this.ownerId === '` style breakout (adjust to the
  app's exact `$where` string construction once the injection point is
  confirmed) — the goal is a response containing records that shouldn't be
  reachable by the current (possibly unauthenticated) caller.
- Use `tool_wrappers/http_request.py` for the manual probe sequence — no
  dedicated NoSQLi tool wrapper exists yet; this stays manual + Haiku
  triage of the JSON diff between baseline and payload responses.

## 4. Evidence Capture
`evidence_schema` requires `extracted_data_sample` (records/fields returned
beyond what the legitimate scalar query would return — e.g. other users'
data, or a modified-count greater than 1 on a scoped update) AND
`boolean_or_timing_diff` (the paired true/false operator response, or the
`$where`-sleep timing pair).

## 5. False-Positive Filtering
- A `$regex`/`$ne` payload returning identical results to the baseline
  means the field isn't passed through to the query unsanitized — the app
  may be using a schema validator (Mongoose schema with strict types)
  that coerces/rejects non-scalar input before it reaches the query.
- Framework-level request body validation (JSON schema validation
  middleware) rejecting the operator object with a 400 is the control
  working as intended — TESTED_CLEAN, not a bypass to chase further unless
  a schema gap is found elsewhere.

## 6. CVSS Vector Construction
- Cross-user data read via operator injection (no auth bypass):
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (~6-7 Medium/High depending on PR).
- Auth bypass via NoSQLi login (`{"email": {"$ne": null}, "password": {"$ne": null}}`):
  `PR:N/UI:N/S:U/C:H/I:L` at minimum (~9.x Critical) — same tier as SQLi auth bypass.
- `$where` RCE-adjacent (if the MongoDB deployment allows arbitrary JS
  execution reaching OS-level functions, rare in modern hardened configs):
  escalate to command-injection-tier scoring if actually demonstrated.

## 7. Remediation (by stack)
- Node/Mongoose: enforce strict schema types (reject non-scalar input for
  scalar fields) and use `mongo-sanitize`/`express-mongo-sanitize`
  middleware to strip `$`-prefixed keys from request bodies before they
  reach any query.
- Disable `$where`/server-side JS execution entirely if the application
  doesn't genuinely need it (`javascriptEnabled: false` at the MongoDB
  server config level).
- General: never pass `req.body`/`req.query` objects directly into a query
  filter — always construct the filter object explicitly field-by-field
  with type coercion (`String(input.id)`, not `input` as-is).
