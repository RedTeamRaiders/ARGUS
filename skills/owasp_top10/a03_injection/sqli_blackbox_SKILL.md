---
owasp_id: A03:2021
vuln_class: sqli
test_mode: blackbox
requires: []
primitive: sqli_read
evidence_schema:
  required_proof: [extracted_data_sample, boolean_or_timing_diff]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: SQL Injection — Black Box

## 1. Recon — Attack Surface Mapping
- Every parameter that touches a query: login forms, search boxes, sort/filter
  params, ID path segments (`/products/<id>`), cookies, headers (`X-Forwarded-For`,
  `User-Agent`) that logging layers sometimes insert into SQL unsafely.
- Pull candidate params from `arjun` (live discovery) and `paramspider`/`gau`
  (historical) output already collected during active/passive recon — don't
  re-crawl, reuse `context.endpoints`.
- Fingerprint the backend early: error pages, `X-Powered-By`, ORM-style error
  strings (`SQLSTATE`, `ORA-`, `sqlite3.OperationalError`) narrow technique
  selection before the first payload goes out.

## 2. Detection Methodology — Probe Sequence
Manual confirmation before any automated tool, in this order:
1. `'` → does the response change (error, blank page, 500)?
2. `''` (escaped) → does it return to normal? If yes, `'` broke a string context.
3. `' AND 1=1--` vs `' AND 1=2--` → boolean differential on an otherwise
   identical request is the strongest blackbox signal.
4. If no visible difference: time-based — `' AND SLEEP(5)--` (MySQL) /
   `'; WAITFOR DELAY '0:0:5'--` (MSSQL) / `pg_sleep(5)` (Postgres) and measure
   response latency against a baseline request.
5. Never jump straight to sqlmap — it burns a lot of requests and looks like
   a scanner. Confirm the single injectable parameter manually first.

## 3. Exploitation Path — Tool Invocation
Once step 2 confirms a parameter is injectable, hand it to `tool_wrappers/sqlmap.py`
scoped tightly to that parameter — never run sqlmap against an unconfirmed surface:
```python
import tool_wrappers.sqlmap as sqlmap
result = await sqlmap.run(
    target=url,
    param=confirmed_param,
    level=1, risk=1,                 # start conservative — bump only if needed
    technique="BEUSTQ",              # try all technique families
)
```
- `result["injectable"]`, `result["db_type"]`, `result["injectable_params"]`
  come back structured — never feed sqlmap's raw stdout to Claude.
- If error-based confirms (`result["techniques"]` includes `"UNION query"` or
  `"error-based"`), go straight for a real data sample:
  `sqlmap.run(target=url, param=confirmed_param, level=2, risk=1)` with
  `--dump` behavior implied by level/risk bump, or construct a manual UNION
  payload against the confirmed column count if sqlmap's dump is too slow for
  the rate budget.
- Goal is not "injection exists" — it's extracting a real data sample
  (table/column name via `UNION SELECT`, or an auth bypass that returns an
  authenticated session) to satisfy the evidence schema below.

## 4. Evidence Capture
`evidence_schema` for this vuln class requires BOTH:
- `extracted_data_sample` — an actual row/column/schema value pulled via the
  injection (table name from `sqlite_master`/`information_schema`, or a
  credential hash), not just "the query errored."
- `boolean_or_timing_diff` — the paired true/false or baseline/delayed request
  pair that proves the condition is attacker-controlled, not coincidental
  latency.
`min_tool_confirmations: 2` is satisfied by: (1) the manual boolean/timing
probe, (2) sqlmap's independent confirmation. Both go in `confirmed_by`.

## 5. False-Positive Filtering
- WAF-mangled responses: a 403/406 on `'` alone is a WAF signature match, not
  a SQL error — retest with a URL-encoded or case-varied payload before
  concluding non-injectable.
- Framework auto-escaping: some ORMs (parameterized query builders) return a
  generic 500 on malformed input that looks like a SQL error but isn't
  exploitable — confirm with the boolean differential (step 2.3), not error
  text alone.
- Network jitter can fake a timing diff — always run the SLEEP probe 2x
  against a stable baseline before trusting a timing-based signal.

## 6. CVSS Vector Construction
Base on what was actually extracted:
- Read-only data extraction (no auth bypass, no write): `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (~7.5 High)
- Auth bypass via SQLi (login as arbitrary user): add `C:H/I:L` at minimum, often `I:H` if admin reachable (~9.x Critical)
- Blind/time-based only, no data confirmed yet: downgrade confidence, not just severity — this isn't `confirmed=True` until a data sample exists.
- Write access confirmed (`INSERT`/`UPDATE` via stacked queries where DB allows): `C:H/I:H/A:H`.

## 7. Remediation (by stack)
- Node/Express + raw `mysql`/`pg` driver: migrate to parameterized queries
  (`?`/`$1` placeholders) or an ORM (Sequelize/Prisma/Knex) with query builder
  methods, never string concatenation.
- Python (Flask/Django raw SQL): use `cursor.execute(query, params)` tuple
  binding, never f-strings/`%` formatting into SQL.
- Java/Spring with JPA/Hibernate: use named parameters (`:param`) in JPQL,
  never `createQuery` string concatenation.
- PHP: PDO prepared statements (`->prepare()`/`->bindParam()`), never raw
  `mysqli_query` with interpolated input.
- Defense in depth regardless of stack: least-privilege DB account (no
  `DROP`/`FILE` grants for the app user), parameterized queries first, WAF
  signatures second — never the other way around.
