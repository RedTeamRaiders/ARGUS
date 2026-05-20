# ARGUS Build Progress

This file is updated after every committed checkpoint.
If quota runs out, resume from the **Next Step** section below.

---

## Current Status

**Phase:** 2 — Core Engine
**Status:** COMPLETE
**Last Updated:** 2026-05-19
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

### Phase 3 — Threat Model Agent ⏳
- [ ] `skills/threat_model/SKILL.md`
- [ ] `skills/threat_model_ai/SKILL.md`
- [ ] `prompts/threat_model.md`
- [ ] `agents/threat_model.py`
- [ ] `templates/threat_model_report.md.j2`
- [ ] `data/mitre_atlas.json`
- [ ] `data/mitre_attack.json`
- [ ] `data/owasp_llm_top10.json`

### Phase 4 — Code Review Agent ⏳
- [ ] `skills/code_review/SKILL.md`
- [ ] `prompts/code_review.md`
- [ ] `agents/code_review.py`
- [ ] `tool_wrappers/semgrep.py`
- [ ] `tool_wrappers/bandit.py`
- [ ] `tool_wrappers/trufflehog.py`
- [ ] `templates/code_review_report.md.j2`

### Phase 5 — ARGUS Crawler (Playwright) ⏳
- [ ] `tool_wrappers/argus_crawler/__init__.py`
- [ ] `tool_wrappers/argus_crawler/crawler.py`
- [ ] `tool_wrappers/argus_crawler/form_detector.py`
- [ ] `tool_wrappers/argus_crawler/payload_injector.py`
- [ ] `tool_wrappers/argus_crawler/monitor.py`
- [ ] `tool_wrappers/argus_crawler/auth_handler.py`
- [ ] `tool_wrappers/argus_crawler/rich_text_handler.py`
- [ ] `tool_wrappers/argus_crawler/evidence_collector.py`

### Phase 6 — Bug Bounty Agent ⏳
- [ ] `skills/bug_bounty/SKILL.md`
- [ ] `prompts/bug_bounty.md`
- [ ] `agents/bug_bounty.py`
- [ ] `tool_wrappers/nmap.py`
- [ ] `tool_wrappers/nuclei.py`
- [ ] `tool_wrappers/gobuster.py`
- [ ] `tool_wrappers/ffuf.py`
- [ ] `tool_wrappers/httpx.py`
- [ ] `tool_wrappers/katana.py`
- [ ] `tool_wrappers/gau.py`
- [ ] `tool_wrappers/linkfinder.py`
- [ ] `tool_wrappers/dalfox.py`
- [ ] `tool_wrappers/sqlmap.py`
- [ ] `data/payload_knowledge/xss_reflected.json`
- [ ] `data/payload_knowledge/xss_stored.json`
- [ ] `data/payload_knowledge/xss_dom.json`
- [ ] `data/payload_knowledge/xss_blind.json`
- [ ] `data/payload_knowledge/xss_waf_bypass.json`
- [ ] `data/payload_knowledge/xss_file_upload.json`
- [ ] `data/payload_knowledge/sqli_patterns.json`
- [ ] `data/payload_knowledge/ssrf_patterns.json`
- [ ] `data/payload_knowledge/ssti_patterns.json`
- [ ] `templates/bug_bounty_report.md.j2`

### Phase 7 — Pentest Agent ⏳
- [ ] `skills/pentest_blackbox/SKILL.md`
- [ ] `skills/pentest_whitebox/SKILL.md`
- [ ] `prompts/pentest.md`
- [ ] `agents/pentest.py`
- [ ] `tool_wrappers/hydra.py`
- [ ] `tool_wrappers/searchsploit.py`
- [ ] `tool_wrappers/impacket.py`
- [ ] `tool_wrappers/linpeas.py`
- [ ] `tool_wrappers/shodan.py`
- [ ] `tool_wrappers/trufflehog.py`
- [ ] `data/payload_knowledge/reverse_shells.json`
- [ ] `templates/pentest_report.md.j2`

### Phase 8 — Red Team Agent ⏳
- [ ] `skills/red_team/SKILL.md`
- [ ] `prompts/red_team.md`
- [ ] `agents/red_team.py`
- [ ] `tool_wrappers/bloodhound.py`
- [ ] `tool_wrappers/crackmapexec.py`
- [ ] `templates/red_team_report.md.j2`

### Phase 9 — AI Red Team + Voice ⏳
- [ ] `skills/ai_redteam/SKILL.md`
- [ ] `skills/voice_redteam/SKILL.md`
- [ ] `prompts/ai_redteam.md`
- [ ] `prompts/voice_redteam.md`
- [ ] `agents/ai_redteam.py`
- [ ] `agents/voice_redteam.py`
- [ ] `tool_wrappers/voicetest_client.py`
- [ ] `data/voice_attack_scenarios.json`
- [ ] `templates/ai_redteam_report.md.j2`
- [ ] `templates/voice_redteam_report.md.j2`

### Phase 10 — Orchestrator + CLI + Reports ⏳
- [ ] `main.py`
- [ ] `orchestrator.py`
- [ ] `prompts/orchestrator.md`
- [ ] `tests/test_tool_wrappers.py`
- [ ] `tests/test_agents.py`

---

## Next Step

**Resume from:** Phase 3, Step 1 — `data/mitre_attack.json` (fetch MITRE ATT&CK data)

**Context for resuming:**
- Working directory: `/opt/Legion_Sec/argus`
- Git branch: `main`
- All Phase 1 files committed (see list above)
- Phase 2 builds: audit logger → session store → auth gate → finding schema → reporter → tool definitions → BaseAgent ReAct loop
- BaseAgent is the most critical file — it defines the human-like Observe→Think→Act→Analyze loop that all agents extend
- Models: Haiku (parse), Sonnet (reason), Opus (deep/adversarial)
- See plan: `/home/sandy/.claude/plans/mellow-seeking-sunset.md`
- See memory: `/home/sandy/.claude/memory/project_argus.md`

---

## Build Log

| Date | Phase | Commit | Files Added |
|---|---|---|---|
| 2026-05-19 | 1 — Scaffold | d627fbe | 13 files: scaffold, config, CLAUDE.md hierarchy, MCP config, dev skills |
| 2026-05-19 | 2 — Core Engine | (pending push) | 7 files: logger, session, auth_gate, reporter, tools, base_agent (ReAct loop) |
