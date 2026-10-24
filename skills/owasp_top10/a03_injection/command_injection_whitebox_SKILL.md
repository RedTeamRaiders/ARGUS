---
owasp_id: A03:2021
vuln_class: command_injection
test_mode: whitebox
requires: [codebase_path]
primitive: command_injection_confirmed
evidence_schema:
  required_proof: [oob_or_timing_confirmation, command_output_sample]
  min_tool_confirmations: 2
  oob_required: true
---

# Skill: OS Command Injection — White Box

## 1. Recon — Taint-Source-to-Sink Mapping
```bash
grep -rn "exec(\|execSync(\|spawn(\|shell_exec\|system(\|subprocess\.\(run\|call\|Popen\)" --include="*.py" --include="*.js" --include="*.php" .
```
For every hit, check: is `shell=True` (Python), is the Node call
`exec`/`execSync` (shell-interpreting) rather than `execFile`/`spawn` with
an array, or is PHP's call unescaped. Then trace the command string's
construction back to a user-controlled source.

## 2. Detection Methodology — Trace Pattern
A sink is genuine when: (1) a shell-interpreting call is used, (2) the
command string contains a user-controlled variable, (3) no
allowlist/escaping function sits between source and sink. `execFile`/`spawn`
with an argument array is NOT exploitable via shell metacharacters even with
tainted input — deprioritize those immediately, they're the wrong sink shape.

## 3. Exploitation Path — Confirm in Runtime
Same OOB-first confirmation as blackbox §3, now targeted precisely at the
traced parameter — skip the broad nuclei sweep since the exact injectable
call site is already known from source.

## 4. Evidence Capture
Same `evidence_schema` as blackbox, plus `file:line` of the shell-interpreting
call and confirmation of which taint source feeds it.

## 5. False-Positive Filtering
A `shell=True`/`exec()` call fed only by a hardcoded command with no user
input anywhere in the string is not exploitable — verify every `%s`/`+`/f-string
segment's origin before flagging. A call that looks dangerous but is fed
by an enum validated against a strict allowlist earlier in the function is
TESTED_CLEAN, not SKIPPED — note the allowlist location as the control.

## 6. CVSS Vector Construction
Identical scoring to blackbox (see `command_injection_blackbox_SKILL.md` §6).

## 7. Remediation (by stack)
Same as blackbox §7, plus: add a semgrep/bandit rule to CI that flags new
`shell=True`/`exec`/`execSync`/`shell_exec` call sites for manual review
before merge.
