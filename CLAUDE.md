# ARGUS — Autonomous Reconnaissance & General-purpose Universal Security System

AI-powered security agent that behaves like a human pentester, not a DAST scanner.
7 agents: Pentesting, Bug Bounty, Red Team, AI Red Team, Voice Red Team, Threat Model, Code Review.

## Run
- `python main.py`            — launch ARGUS interactive menu
- `pytest tests/`             — run all tests
- `python -m agents.pentest`  — run single agent directly

## Architecture
- `agents/`          — 7 sub-agents, each has a skill file and system prompt
- `shared/`          — auth_gate, session store, finding schema, reporter, audit logger
- `tool_wrappers/`   — external tools: raw output → structured JSON only
- `skills/`          — agent methodology files loaded into system prompt at runtime
- `prompts/`         — Claude system prompts per agent
- `.mcp.json`        — all MCP server configurations

## Critical Rules
1. `shared/auth_gate.py` MUST pass before ANY active agent runs — no exceptions
2. Every finding MUST have an `evidence` field containing direct tool output
3. Tool wrappers return structured JSON only — never pass raw text to Claude
4. Critical/High findings require 2+ independent tool confirmations
5. XSS findings require Playwright headless verification before reporting
6. Never commit `.env`, `data/sessions.db`, `.claude/settings.local.json`
7. Max 30 req/min default — agents behave like humans, not scanners

## Models
- Haiku 4.5   → tool output parsing, deduplication, classification
- Sonnet 4.6  → agent reasoning, STRIDE/ATT&CK mapping, report writing
- Opus 4.7    → attack chain construction, adversarial reasoning, AI threat modeling

## Entry Points
Read `shared/reporter.py` for the finding schema.
Read `agents/base_agent.py` for the ReAct loop interface.
Read `agents/CLAUDE.md` before editing any agent.
Read `tool_wrappers/CLAUDE.md` before editing any tool wrapper.
