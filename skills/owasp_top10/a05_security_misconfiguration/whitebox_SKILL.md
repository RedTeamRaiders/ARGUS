---
owasp_id: A05:2021
vuln_class: security_misconfiguration
test_mode: whitebox
requires: [codebase_path]
primitive: misconfig_exposed
evidence_schema:
  required_proof: [exposed_resource_sample, config_detail_disclosed]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Security Misconfiguration — White Box

## 1. Recon — Direct Configuration Review
- Read the actual config files/env templates: `settings.py`,
  `.env.example` vs any real `.env` accidentally committed, `nginx.conf`,
  `docker-compose.yml`, CI/CD pipeline configs.
- Check: `DEBUG`/`NODE_ENV` default values, `ALLOWED_HOSTS`/CORS allowlist
  entries, whether secrets are read from env vars or hardcoded, whether
  default credentials from a sample config were ever changed.
- `git log --all --full-history -- "*.env"` and `git log -S "password" --all`
  — deleted files and old commits can still contain live secrets.

## 2. Detection Methodology — Trace Pattern
Flag: `DEBUG = True` (or equivalent) with no environment-based override
visible at deploy time; `CORS_ALLOW_ALL_ORIGINS`/`Access-Control-Allow-Origin: *`
hardcoded; secrets with real-looking values (not `CHANGEME`/placeholder
patterns) committed to the repo; a `.dockerignore`/`.gitignore` that
doesn't exclude `.env`.

## 3. Exploitation Path — Confirm in Runtime
Confirm each source-level finding is actually live in the deployed
instance, not just present in a dev-only branch/config — probe the running
target exactly as in blackbox §2–3 for the specific misconfigurations
identified from source.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line`/commit reference for
the source-level misconfiguration.

## 5. False-Positive Filtering
A `DEBUG=True` default in `settings.py` that's always overridden by an
environment variable in every deployment manifest (verify the actual
deploy config, not just the code default) is TESTED_CLEAN for the
production target, though still worth noting as a weak default for
defense-in-depth.

## 6. CVSS Vector Construction
Identical scoring logic to blackbox (see `blackbox_SKILL.md` §6 in this
directory).

## 7. Remediation (by stack)
Same as blackbox §7, plus: add a pre-commit hook / CI secret-scanner
(`trufflehog`, already in `tool_wrappers/`) to catch committed secrets
before merge, and a config-linter step that fails CI if `DEBUG`/wildcard
CORS is set in a production-targeted config file.
