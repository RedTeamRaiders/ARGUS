---
owasp_id: A10:2021
vuln_class: ssrf
test_mode: blackbox
requires: []
primitive: ssrf
evidence_schema:
  required_proof: [internal_fetch_confirmation, response_data_sample]
  min_tool_confirmations: 2
  oob_required: true
---

# Skill: Server-Side Request Forgery — Black Box

## 1. Recon — Attack Surface Mapping
- Any feature where the server fetches a URL on the user's behalf:
  profile-image-by-URL, webhook/callback URL registration, PDF/report
  generation from a URL, link-preview generators, import-from-URL
  features, SSO/OAuth metadata-endpoint discovery.
- Note the cloud provider if identifiable (response headers, error
  messages) — the metadata endpoint differs: `169.254.169.254` (AWS/most),
  `metadata.google.internal` (GCP), `169.254.169.254/metadata` (Azure, with
  a required `Metadata: true` header).

## 2. Detection Methodology — Probe Sequence
1. OOB confirmation first (satisfies `oob_required: true`): point the
   URL-accepting field at an attacker-controlled listener
   (`http://<collaborator-domain>/ssrf-test-<token>`) and confirm the
   callback fires — this proves the server makes outbound requests from
   user-supplied URLs at all, before probing anything internal.
2. Internal probing: `http://127.0.0.1/`, `http://localhost/`,
   `http://[::1]/`, common internal service ports
   (`:6379` Redis, `:9200` Elasticsearch, `:8080`/`:3000` internal apps).
3. Cloud metadata probing (only after OOB confirms outbound fetch works):
   `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   (AWS), adjust per identified cloud provider.
4. Protocol confusion: try `file://`, `dict://`, `gopher://` schemes if the
   fetch library doesn't restrict to `http(s)://` — `file://` can read
   local files directly, `gopher://` can smuggle raw TCP payloads to
   internal services.
5. Bypass filters if a naive allowlist/denylist is in place: DNS rebinding,
   decimal/octal IP encoding (`http://2130706433/` = 127.0.0.1), redirects
   (point the accepted URL at an attacker server that 302-redirects to the
   internal target).

## 3. Exploitation Path — Demonstrate Impact
- If cloud metadata is reachable: extract IAM role credentials
  (temporary access key/secret/token) — this is the textbook high-impact
  SSRF chain (see Part 4: `ssrf` + `cloud_metadata_exposed` →
  `credential_theft`).
- If an internal service is reachable: identify what it is (Redis, an
  internal admin API) and demonstrate a read (not a destructive write) —
  e.g. a Redis `INFO` command via a crafted gopher payload, or an internal
  API's unauthenticated data endpoint.

## 4. Evidence Capture
`evidence_schema` requires `internal_fetch_confirmation` (the OOB callback
log entry showing the server made the outbound request) AND
`response_data_sample` (actual content returned from the internal
target/metadata endpoint — redacted of any live credentials per Part 6's
evidence hygiene before it reaches a report, but the raw capture itself is
the proof).

## 5. False-Positive Filtering
- A URL field that's validated against an allowlist of known-good domains
  server-side (and the OOB probe is correctly rejected) is TESTED_CLEAN —
  confirm the allowlist can't be bypassed via redirect/DNS tricks before
  concluding fully clean.
- A "fetch failed, storing the URL as a literal string" fallback behavior
  (seen in some apps) is NOT SSRF — no outbound request was actually made;
  it may still be an injection vector for a different vuln class (stored
  XSS via the stored literal), note separately if relevant.

## 6. CVSS Vector Construction
- Cloud credential theft via metadata endpoint: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H` at minimum (~9.5+ Critical) — full cloud-account blast radius depending on the role's permissions.
- Internal service read access (no credential theft): `C:H/I:N/A:N` (~7-8 High).
- OOB confirmed but no internal/metadata target reachable (fully
  firewalled internal network): lower severity — note the outbound SSRF
  primitive exists for future chain potential, score conservatively
  (~Medium) until a reachable internal target is found.

## 7. Remediation (by stack)
- Validate and restrict destination: resolve the URL's hostname and reject
  private/link-local/metadata IP ranges (`127.0.0.0/8`, `169.254.0.0/16`,
  `10.0.0.0/8`, etc.) server-side before fetching, and re-validate after
  any redirect (don't trust the first-hop validation alone).
- Disable unused URL schemes in the fetch library (`file://`, `gopher://`,
  `dict://`) — restrict to `http(s)://` explicitly.
- Network-level defense in depth: block the cloud metadata endpoint from
  application-tier instances via a network policy/IMDSv2 enforcement (AWS)
  so even a successful SSRF can't reach it.
