---
owasp_id: A03:2021
vuln_class: sqli
test_mode: whitebox
requires: [codebase_path]
primitive: sqli_read
evidence_schema:
  required_proof: [extracted_data_sample, boolean_or_timing_diff]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: SQL Injection — White Box

## 1. Recon — Taint-Source-to-Sink Mapping
- Grep for every raw query-construction call first — `grep -rn "SELECT\|INSERT\|UPDATE\|DELETE" --include="*.py" --include="*.js" --include="*.java" --include="*.php"`,
  then filter to ones built via string concatenation/formatting (`+`, f-string,
  `%`, template literals) rather than driver placeholders.
- For each hit, trace the source: does the interpolated variable originate
  from `request.args`/`req.query`/`req.body`/a path param? If it originates
  from a config value or a hardcoded constant, it's not reachable — deprioritize.
- Build the source→sink chain explicitly: `route handler → service/model layer
  → raw query execution`. Note every layer the value passes through — a
  sanitizer anywhere in that chain changes the finding from CONFIRMED to
  TESTED_CLEAN.

## 2. Detection Methodology — Trace Pattern
A sink is a genuine candidate when ALL of:
1. The query string contains a variable, not just literals.
2. That variable traces back to user-controlled input (not session-derived
   IDs that were themselves validated against the authenticated user).
3. No parameterization/escaping call sits between source and sink (`?`
   placeholders, `bindParam`, an ORM builder method call instead of raw SQL).
4. No type coercion neutralizes it before the sink (e.g. the param is cast
   to `int()` before concatenation — not injectable as a string, still worth
   noting as a near-miss for the false-positive log).

Grep patterns that generalize well across stacks:
```bash
# Raw concatenation into SQL (adjust extensions per stack present)
grep -rnE "(SELECT|INSERT|UPDATE|DELETE).*(\+|f['\"]|\{.*\}|%s|\.format\()" --include="*.py" --include="*.js" .
# ORM escape hatches that bypass parameterization
grep -rn "\.raw(\|\.query(\|execute_raw\|rawQuery" .
```

## 3. Exploitation Path — Confirm in Runtime
Code review alone never satisfies the evidence schema — the finding must be
dynamically confirmed, same as blackbox, once the source→sink trace narrows
the candidate parameter:
```python
import tool_wrappers.sqlmap as sqlmap
result = await sqlmap.run(
    target=url, param=traced_param, level=1, risk=1, technique="BEUSTQ",
)
```
- White box advantage: you know the exact column/table names from the schema
  (migrations, ORM models) — use them to craft a precise UNION payload
  instead of letting sqlmap brute-force schema discovery, which is faster
  and quieter.
- If the traced sink is in a code path that requires authentication, obtain
  a low-privilege session first (white box gives you test credentials) —
  blackbox can't reach this surface at all, which is exactly why this file
  exists separately.

## 4. Evidence Capture
Same `evidence_schema` as blackbox (`extracted_data_sample` +
`boolean_or_timing_diff`), PLUS whitebox's own mandatory addition per the
white box reporting standard in `pentest_whitebox/SKILL.md`: a `file:line`
reference to the vulnerable query construction. A whitebox SQLi finding
without the source location is incomplete — it's indistinguishable from a
blackbox finding to the person who has to fix it.

## 5. False-Positive Filtering
- An f-string/concatenation hit where the interpolated value is a hardcoded
  enum (`f"SELECT * FROM {TABLE_NAME}"` where `TABLE_NAME` is a module
  constant) is not injectable — log it as TESTED_CLEAN with the reason, not
  as a skipped grep hit.
- A sink that looks raw but is actually inside an ORM's own internals (e.g.
  the ORM library's source, not application code) is out of scope for this
  category — that's A06 (vulnerable component), not an app-level finding.
- Double-check parameter type coercion: `int(request.args["id"])` before
  concatenation means that specific call site is not exploitable even if the
  same route has other unvalidated params feeding the same query.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `sqli_blackbox_SKILL.md` §6) — the
test mode doesn't change impact, only how the finding was discovered.
Whitebox findings often score the same or higher for confidence (not CVSS
itself) because the exact data model is known, so `extracted_data_sample`
can demonstrate maximum reachable impact rather than a representative
sample.

## 7. Remediation (by stack)
Same stack-specific fixes as blackbox (§7), with one whitebox-only addition:
recommend a **static analysis gate** in CI (bandit for Python, semgrep rules
for raw-query patterns, ESLint plugin for Node) that fails the build on new
unparameterized query construction — this prevents regression, which a
blackbox-only remediation can't offer.
