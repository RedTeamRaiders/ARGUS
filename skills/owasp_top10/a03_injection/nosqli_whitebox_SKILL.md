---
owasp_id: A03:2021
vuln_class: nosqli
test_mode: whitebox
requires: [codebase_path]
primitive: nosqli_read
evidence_schema:
  required_proof: [extracted_data_sample, boolean_or_timing_diff]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: NoSQL Injection — White Box

## 1. Recon — Taint-Source-to-Sink Mapping
```bash
grep -rn "\$where\|find(req\.\|findOne(req\.\|updateMany(req\.\|\.aggregate(" --include="*.js" .
```
Trace every query-building call that passes `req.body`/`req.query` directly
(or a shallow spread of it) into a Mongoose/MongoDB driver call without an
intervening schema-cast or explicit field whitelist.

## 2. Detection Methodology — Trace Pattern
A sink is genuine when: (1) the filter object passed to `find`/`update`
includes a key or sub-object taken directly from request input, (2) no
`mongo-sanitize` call or Mongoose strict-schema cast happens first, (3) the
field in question isn't coerced to a primitive type (`String()`, `Number()`)
before use.

## 3. Exploitation Path — Confirm in Runtime
Same operator-injection and `$where`-timing probes as blackbox §2–3, aimed
precisely at the traced field — white box tells you exactly which operators
the field's type would accept (e.g. if it's cast through a known allowlist
of operators somewhere upstream, that narrows which payloads are worth
trying).

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the unsanitized
filter-construction call.

## 5. False-Positive Filtering
A `find(req.query)`-shaped call that's actually preceded by
`express-mongo-sanitize` applied as global middleware (check
`app.use(mongoSanitize())` in the main server file) is TESTED_CLEAN — verify
the middleware is actually registered and covers this route before flagging
the sink as live.

## 6. CVSS Vector Construction
Identical scoring to blackbox (see `nosqli_blackbox_SKILL.md` §6).

## 7. Remediation (by stack)
Same as blackbox §7, plus: add a semgrep rule flagging direct `req.body`/
`req.query` objects passed as MongoDB filter arguments without going
through an explicit allowlist/cast function first.
