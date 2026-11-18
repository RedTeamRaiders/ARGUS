# Contributing to ARGUS

ARGUS is an AI-driven pentesting agent, not a scanner wrapper. Contributions should
make it reason more like a human tester — better evidence discipline, better tool
coverage, better methodology — not just add features for their own sake.

## Before you start

Read the `CLAUDE.md` in the directory you're touching before opening a PR:

- Root [`CLAUDE.md`](CLAUDE.md) — architecture, critical rules, model tiers.
- [`agents/CLAUDE.md`](agents/CLAUDE.md) — before editing any agent or the ReAct loop in `agents/base_agent.py`.
- [`tool_wrappers/CLAUDE.md`](tool_wrappers/CLAUDE.md) — before adding or editing a tool wrapper.
- [`shared/CLAUDE.md`](shared/CLAUDE.md) — before touching the session store, finding schema, or audit logger.

These aren't style guides — they encode decisions (like why evidence is mandatory, or
why tool wrappers never hand raw text to Claude) that took debugging real false
positives to arrive at. A PR that contradicts one of them needs to explain why in the
description, not just override it silently.

## Non-negotiable invariants

These are enforced by the codebase and by review, in this priority order:

1. **Every `Finding` must carry non-empty `evidence`** — direct tool output, not a
   paraphrase. `shared/reporter.py` raises on construction if it's missing; don't work
   around that in a PR.
2. **Tool wrappers return structured JSON only.** Raw tool stdout never reaches Claude
   directly — if you add a wrapper under `tool_wrappers/`, it parses the tool's output
   into the schema the rest of the codebase expects. See `tool_wrappers/CLAUDE.md`.
3. **Critical/High findings require 2+ independent tool confirmations** before
   `confirmed=True`. Don't special-case a tool to skip this.
4. **XSS findings require Playwright headless verification** (`shared/xss_verification.py`)
   before they can ship. If you add an agent or pipeline that can emit XSS findings,
   wire the gate in — see the recent `red_team`/`bug_bounty`/`voice_redteam` commits for
   the pattern.
5. **`Scope.contains()` is checked on every tool call** in `agents/base_agent.py::_act`.
   ARGUS has no separate authorization gate — operators are trusted to confirm
   authorization out of band, and scope is the only in-code boundary. Don't add code
   paths that call a tool before this check runs.
6. **Never commit** `.env`, `data/sessions.db`, `data/.salt`, or
   `.claude/settings.local.json`. These are already in `.gitignore`; double-check
   `git status` before pushing if you've been testing locally.

## Pull requests

- **One focused change per PR.** A new tool wrapper, a fix to the coverage gate, a new
  skill file — pick one. If a change has independent parts, split it.
- **State what you tested.** For a tool wrapper: the raw tool output you fed it and the
  structured JSON it produced. For an agent change: which module(s) you ran end-to-end.
  For a skill file: which agent loaded it and what changed in its behavior.
- **Run the test suite** (`pytest tests/`) before opening the PR, and add a test if
  you're touching `shared/coverage_gate.py`, `shared/pivot_scanner.py`,
  `shared/evidence_hygiene.py`, or `shared/xss_verification.py` — these are the
  mechanisms that keep findings honest, and they're currently the thinnest-tested part
  of the codebase. Regressions here are worse than a missing feature.
- **New agent or tool wrapper?** Use the `add-agent` / `add-tool-wrapper` skill
  conventions already in this repo rather than hand-rolling the scaffolding — keeps new
  modules consistent with the existing seven.
- A PR with no description of the problem and what you verified is a request for
  changes, not a merge candidate.

## Adding a skill file

Skills under `skills/<module>/` are methodology, not code — they get loaded into an
agent's system prompt at runtime. When adding or editing one:

- Keep target-specific literals (exact creds, exact routes, a specific CTF's unlock
  key) out of it. Skills should generalize; if you need a fixture for regression
  testing against a specific lab, that belongs in `tests/fixtures/`, not in a skill
  that ships to every engagement.
- If the skill is for a module that already has a coverage manifest (`pentest`,
  `bug_bounty`), check whether it needs a corresponding entry in
  `shared/manifests/owasp_top10.py` so coverage tracking stays accurate.

## Issues

- One problem per issue. Include the ARGUS commit/version, the module (`pentest`,
  `bug_bounty`, etc.), and what you expected vs. what happened.
- For a false positive or false negative in a finding, include the `evidence` field
  from the finding and the raw tool output it came from — that's usually enough to
  tell whether the bug is in the tool wrapper, the agent's reasoning, or a gate that
  should have caught it.

## Security

Do not open a public issue for a vulnerability in ARGUS itself (as opposed to a
finding ARGUS produced about a target). See [SECURITY.md](SECURITY.md).
