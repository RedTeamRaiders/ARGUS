# Security Policy

ARGUS is an autonomous offensive-security agent. It is built to be run against real
targets, which means both "bugs in ARGUS" and "how ARGUS behaves against a target" are
in scope for this policy — they're handled differently below.

## Supported versions

There is no tagged release yet — `main` is the only line, and security fixes land
there. Once releases start, this section will be updated to name a supported line, and
fixes will not be backported further than that.

## Reporting a vulnerability in ARGUS

**Do not open a public issue for a security vulnerability.**

Report privately through **GitHub Security Advisories**: the **Security** tab →
**Report a vulnerability** on this repository. This is the only reporting channel.

Please include:
- A description of the vulnerability and its expected impact.
- The commit hash you tested against.
- Runtime environment (OS, Python version, which agent/module).
- Minimal reproduction steps.
- Logs or evidence with sensitive data (target hostnames, credentials, API keys)
  redacted.
- Suggested remediation, if you have one.

**Do not send** real API keys, real target credentials, or unredacted client/target
data as part of a report.

## Scope and authorized use

ARGUS is an offensive-security tool with **no enforced authorization gate** — this is
a deliberate design decision, documented in [`CLAUDE.md`](CLAUDE.md), not an oversight.
Operators are trusted to confirm written authorization out of band before pointing
ARGUS at a target; the only in-code boundary is `Scope.contains()`
(`shared/session.py`), checked on every tool call in `agents/base_agent.py::_act`, which
keeps agents inside the target/scope the operator entered.

**Use ARGUS only against:**
- Systems you own, or lab environments you control;
- Targets you hold explicit written authorization to test (a pentest contract, or a
  bug bounty / VDP program's published scope and rules of engagement).

**Do not use ARGUS to scan, probe, or exploit any system without the explicit
authorization of its owner.** Because there is no software gate preventing this,
responsibility for scope and authorization rests entirely on the operator who launches
a session. A vulnerability report that amounts to "ARGUS let me attack something I
wasn't authorized to attack" will be closed — that's the documented trust model, not a
bug. A report showing `Scope.contains()` can be bypassed or that an agent dispatches a
tool call against a target outside the entered scope **is** a valid, in-scope finding.

## Data handling

- **Session store at rest** (`data/sessions.db`): findings and tool output are
  encrypted with AES-256-GCM when `ARGUS_SESSION_KEY` is set (`shared/at_rest.py`). The
  key is derived via PBKDF2-HMAC-SHA256 (600,000 iterations) from that passphrase,
  salted with a per-install value at `data/.salt` (mode 600, never shared, never
  committed). Without `ARGUS_SESSION_KEY` set, sessions are stored in cleartext and a
  warning is logged — set it before running ARGUS against anything sensitive.
- **Audit trail** (`.claude/audit.log`): every tool call, every Claude call, and every
  finding is timestamped and logged (`shared/logger.py`). This file can contain target
  hostnames, commands run, and finding titles — treat it like engagement data, not a
  throwaway log, and don't commit it.
- **Never commit**: `.env`, `data/sessions.db`, `data/.salt`, or
  `.claude/settings.local.json`. All four are in `.gitignore`. If you've been testing
  locally, run `git status` before pushing — a stray `data/sessions.db` from a real
  engagement is a client-data leak, not a cosmetic mistake.

## Traffic behavior

ARGUS rate-limits its own tool calls to a default of 30 requests/minute
(`agents/base_agent.py`) so automated activity resembles a human tester rather than a
scanner. This is a courtesy to targets and a detection-avoidance-for-authorized-testing
measure, not a safety boundary — it does not prevent an operator from pointing ARGUS at
an out-of-scope or unauthorized target, which is why the scope policy above, not the
rate limiter, is what's actually enforced.

## Trusted inputs

Tool wrappers (`tool_wrappers/`) parse raw tool output into structured JSON before it
reaches Claude — raw text never reaches the model directly (`tool_wrappers/CLAUDE.md`).
That parsing step is itself a trust boundary: a malicious or malformed tool output
designed to break a wrapper's parser, rather than to be reported as a finding, is a
valid vulnerability report against ARGUS.
