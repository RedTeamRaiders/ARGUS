---
owasp_id: A09:2021
vuln_class: logging_monitoring
test_mode: both
requires: []
primitive: logging_gap_confirmed
evidence_schema:
  required_proof: [unlogged_security_event, log_exposure_or_absence]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Security Logging and Monitoring Failures

Single file — blackbox and whitebox converge here. This category is
inherently about absence (did an event get logged, is the log protected)
rather than a distinct exploitation technique per mode; whitebox only adds
the ability to read the logging code directly instead of inferring from
behavior.

## 1. Recon — Attack Surface Mapping
- Security-relevant events to test for logging: failed login attempts
  (especially repeated), privilege escalation attempts, access-control
  denials, input-validation failures (a blocked SQLi/XSS payload).
- Log exposure surface: any endpoint serving raw log files (`/support/logs/`,
  `/debug/logs`, misconfigured log aggregator dashboards reachable without
  auth).
- **Whitebox addition**: read the actual logging calls in auth/authz
  middleware directly — is a failed-auth branch missing a log call
  entirely, or logging only to stdout with no aggregation/alerting?

## 2. Detection Methodology
1. Trigger a clearly loggable security event (several failed logins, an
   obvious SQLi probe that should trip a WAF/IDS signature) and then check
   — via any legitimately accessible admin/log-viewing feature in scope,
   or via whitebox source review — whether the event was captured at all.
2. Probe for exposed log files/endpoints directly (`gobuster`/`feroxbuster`
   against known log-path patterns).
3. **Whitebox**: grep the auth/authz code paths for the absence of a log
   call on the failure branch — `except: pass` swallowing a security
   exception without logging is the classic pattern.

## 3. Exploitation Path
This category rarely has an "exploit" step in the traditional sense — the
deliverable is the demonstration that a security event went unlogged, or
that logs themselves are exposed/tamperable. If logs ARE exposed, treat
the exposure itself as the finding (overlaps A05 Security Misconfiguration
— cross-reference, don't double-report the same root cause under both
categories without noting the overlap).

## 4. Evidence Capture
`evidence_schema` requires `unlogged_security_event` (the triggered
event, paired with confirmation — from an accessible log view or source
review — that no corresponding log entry exists) AND
`log_exposure_or_absence` (either the exposed log file content, or the
specific code location where logging is absent).

## 5. False-Positive Filtering
- Logging that exists but only at DEBUG level (disabled in production) is
  functionally equivalent to absent logging — don't mark TESTED_CLEAN just
  because a `logger.debug()` call exists if it won't fire in the deployed
  configuration.
- A single missed log call in an otherwise comprehensive logging layer is
  lower severity than a systemic absence (no security event logging
  anywhere) — scale the finding to how complete the gap is.

## 6. CVSS Vector Construction
Logging/monitoring gaps don't map cleanly to confidentiality/integrity/
availability impact on their own — score based on what the gap enables: an
undetected brute-force campaign or an undetected intrusion that could have
been caught and stopped earlier. A reasonable default:
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` with a qualitative note that the real
risk is extended dwell time for an attacker, not direct impact — typically
scored Low/Medium on CVSS alone, with the narrative impact (delayed
detection) carrying the actual severity argument in the report.

## 7. Remediation (by stack)
- Log every authentication failure, authorization denial, and input-
  validation rejection with enough context to investigate (timestamp,
  source IP, account/session identifier, the specific check that failed)
  — never log credentials or full session tokens themselves.
- Ship logs to a system the application itself can't modify or delete
  (centralized log aggregation, write-once storage) rather than only local
  files the compromised app server could tamper with.
- Alert on patterns, not just log them: N failed logins from one IP/account
  in a window, repeated authz denials against the same resource.
