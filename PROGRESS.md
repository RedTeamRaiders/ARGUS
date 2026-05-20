# ARGUS Build Progress

This file is updated after every committed checkpoint.
If quota runs out, resume from the **Next Step** section below.

---

## Current Status

**Phase:** 9 — AI Red Team + Voice Red Team
**Status:** COMPLETE
**Last Updated:** 2026-05-20
**Last Commit:** (see below)

---

## Completed Files

### Phase 1 — Scaffold ✅
- [x] `.gitignore`
- [x] `.env.example`
- [x] `.mcp.json`
- [x] `CLAUDE.md`
- [x] `config.py`
- [x] `requirements.txt`
- [x] `.claude/settings.json`
- [x] `.claude/skills/add-agent/SKILL.md`
- [x] `.claude/skills/add-tool-wrapper/SKILL.md`
- [x] `.claude/skills/test-agent/SKILL.md`
- [x] `agents/CLAUDE.md`
- [x] `shared/CLAUDE.md`
- [x] `tool_wrappers/CLAUDE.md`

### Phase 2 — Core Engine (ReAct loop + shared infrastructure) ✅
- [x] `shared/logger.py`
- [x] `shared/session.py`
- [x] `shared/auth_gate.py`
- [x] `shared/reporter.py`
- [x] `shared/tools.py`
- [x] `agents/__init__.py`
- [x] `agents/base_agent.py`

### Phase 3 — Threat Model Agent ✅
- [x] `skills/threat_model/SKILL.md`
- [x] `skills/threat_model_ai/SKILL.md`
- [x] `prompts/threat_model.md`
- [x] `agents/threat_model.py`
- [x] `templates/threat_model_report.md.j2`
- [x] `data/mitre_atlas.json`
- [x] `data/mitre_attack.json`
- [x] `data/owasp_llm_top10.json`

### Phase 4 — Code Review Agent ✅
- [x] `skills/code_review/SKILL.md`
- [x] `prompts/code_review.md`
- [x] `agents/code_review.py`
- [x] `tool_wrappers/semgrep.py`
- [x] `tool_wrappers/bandit.py`
- [x] `tool_wrappers/trufflehog.py`
- [x] `templates/code_review_report.md.j2`

### Phase 5 — ARGUS Crawler (Playwright) ✅
- [x] `tool_wrappers/argus_crawler/__init__.py`
- [x] `tool_wrappers/argus_crawler/crawler.py`
- [x] `tool_wrappers/argus_crawler/form_detector.py`
- [x] `tool_wrappers/argus_crawler/payload_injector.py`
- [x] `tool_wrappers/argus_crawler/monitor.py`
- [x] `tool_wrappers/argus_crawler/auth_handler.py`
- [x] `tool_wrappers/argus_crawler/rich_text_handler.py`
- [x] `tool_wrappers/argus_crawler/evidence_collector.py`

### Phase 6 — Bug Bounty Agent ✅
- [x] `skills/bug_bounty/SKILL.md`
- [x] `prompts/bug_bounty.md`
- [x] `agents/bug_bounty.py`
- [x] `tool_wrappers/nmap.py`
- [x] `tool_wrappers/nuclei.py`
- [x] `tool_wrappers/gobuster.py`
- [x] `tool_wrappers/ffuf.py`
- [x] `tool_wrappers/httpx.py`
- [x] `tool_wrappers/katana.py`
- [x] `tool_wrappers/gau.py`
- [x] `tool_wrappers/linkfinder.py`
- [x] `tool_wrappers/dalfox.py`
- [x] `tool_wrappers/sqlmap.py`
- [x] `data/payload_knowledge/xss_reflected.json`
- [x] `data/payload_knowledge/xss_stored.json`
- [x] `data/payload_knowledge/xss_dom.json`
- [x] `data/payload_knowledge/xss_blind.json`
- [x] `data/payload_knowledge/xss_waf_bypass.json`
- [x] `data/payload_knowledge/xss_file_upload.json`
- [x] `data/payload_knowledge/sqli_patterns.json`
- [x] `data/payload_knowledge/ssrf_patterns.json`
- [x] `data/payload_knowledge/ssti_patterns.json`
- [x] `templates/bug_bounty_report.md.j2`

### Phase 7 — Pentest Agent ✅
- [x] `skills/pentest_blackbox/SKILL.md`
- [x] `skills/pentest_whitebox/SKILL.md`
- [x] `prompts/pentest.md`
- [x] `agents/pentest.py`
- [x] `tool_wrappers/hydra.py`
- [x] `tool_wrappers/searchsploit.py`
- [x] `tool_wrappers/impacket.py`
- [x] `tool_wrappers/linpeas.py`
- [x] `tool_wrappers/shodan.py`
- [x] `data/payload_knowledge/reverse_shells.json`
- [x] `templates/pentest_report.md.j2`

### Phase 8 — Red Team Agent ✅
- [x] `skills/red_team/SKILL.md`
- [x] `prompts/red_team.md`
- [x] `agents/red_team.py`
- [x] `tool_wrappers/bloodhound.py`
- [x] `tool_wrappers/crackmapexec.py`
- [x] `templates/red_team_report.md.j2`

### Phase 9 — AI Red Team + Voice ✅
- [x] `skills/ai_redteam/SKILL.md`
- [x] `skills/voice_redteam/SKILL.md`
- [x] `prompts/ai_redteam.md`
- [x] `prompts/voice_redteam.md`
- [x] `agents/ai_redteam.py`
- [x] `agents/voice_redteam.py`
- [x] `tool_wrappers/voicetest_client.py`
- [x] `data/voice_attack_scenarios.json`
- [x] `templates/ai_redteam_report.md.j2`
- [x] `templates/voice_redteam_report.md.j2`

### Phase 10 — Orchestrator + CLI + Reports ⏳
- [ ] `main.py`
- [ ] `orchestrator.py`
- [ ] `prompts/orchestrator.md`
- [ ] `tests/test_tool_wrappers.py`
- [ ] `tests/test_agents.py`

---

## Next Step

**Resume from:** Phase 10 — Orchestrator + CLI + Reports

**Files to build:**
1. `main.py` — ARGUS banner, interactive menu (options 1-7 + 0 exit), session init, agent dispatch
2. `orchestrator.py` — routes menu selection to correct agent, manages session lifecycle, triggers report generation
3. `prompts/orchestrator.md` — orchestrator system prompt for meta-reasoning across agent outputs
4. `tests/test_tool_wrappers.py` — unit tests for all tool wrappers using fixture files
5. `tests/test_agents.py` — integration tests for agent run() methods
6. `tests/fixtures/` — sample outputs for each tool wrapper

**Context for resuming:**
- Working directory: `/opt/Legion_Sec/argus`
- Git branch: `main`
- Phases 1-9 all committed (see build log)
- All 7 agents built: pentest, bug_bounty, red_team, ai_redteam, voice_redteam, threat_model, code_review
- BaseAgent in `agents/base_agent.py` provides ReAct loop
- Finding schema in `shared/reporter.py`
- Models: Haiku (parse), Sonnet (reason), Opus (deep/adversarial)
- ARGUS banner/menu design in plan: `/home/sandy/.claude/plans/mellow-seeking-sunset.md`

---

## Build Log

| Date | Phase | Commit | Files Added |
|---|---|---|---|
| 2026-05-19 | 1 — Scaffold | d627fbe | 13 files: scaffold, config, CLAUDE.md hierarchy, MCP config, dev skills |
| 2026-05-19 | 2 — Core Engine | 1a4a90d | 7 files: logger, session, auth_gate, reporter, tools, base_agent (ReAct loop) |
| 2026-05-19 | 3 — Threat Model | 3997800 | 8 files: mitre JSONs, STRIDE/AI skills, threat_model prompt, agent, report template |
| 2026-05-19 | 4 — Code Review | e4f265f | 7 files: SAST skill, prompt, agent, semgrep/bandit/trufflehog wrappers, report template |
| 2026-05-19 | 5 — Crawler | a41c53f | 8 files: BFS crawler, form_detector (all editor types), payload_injector, monitor, auth_handler, rich_text_handler, evidence_collector |
| 2026-05-19 | 6 — Bug Bounty | 7619f61 | 24 files: skill, prompt, agent (XSS pipeline), 9 tool wrappers, 9 payload knowledge JSONs, report template |
| 2026-05-20 | 7 — Pentest | 9a6f9ca | 11 files: black/white box skills, prompt, agent, hydra/searchsploit/impacket/linpeas/shodan wrappers, reverse_shells, report template |
| 2026-05-20 | 8 — Red Team | (pending) | 6 files: ATT&CK skill, prompt, agent (APT sim + detection gap analysis), bloodhound, crackmapexec, report template |
| 2026-05-20 | 9 — AI Red Team + Voice | (pending) | 10 files: ai_redteam + voice_redteam skills/prompts/agents, voicetest_client, voice_attack_scenarios, 2 report templates |
