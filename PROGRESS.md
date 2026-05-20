# ARGUS Build Progress

This file is updated after every committed checkpoint.
If quota runs out, resume from the **Next Step** section below.

---

## Current Status

**Phase:** 4 — Code Review Agent
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

**Resume from:** Phase 5, Step 1 — `tool_wrappers/argus_crawler/__init__.py`

**Context for resuming:**
- Working directory: `/opt/Legion_Sec/argus`
- Git branch: `main`
- Phase 1 + 2 + 3 committed (see build log)
- Phase 3 adds: MITRE data JSONs, STRIDE/AI skill files, threat_model prompt, ThreatModelAgent (Opus for STRIDE + AI threats), Jinja2 report template
- ThreatModelAgent phases: _identify_assets → _run_stride (Opus) → _build_attack_trees → _analyze_ai_threats (Opus) → _score_threats → _generate_recommendations
- Phase 4 (code_review) needs: SKILL.md, prompt, agent, semgrep/bandit/trufflehog wrappers, report template
- Models: Haiku (parse), Sonnet (reason), Opus (deep/adversarial)
- See plan: `/home/sandy/.claude/plans/mellow-seeking-sunset.md`

---

## Build Log

| Date | Phase | Commit | Files Added |
|---|---|---|---|
| 2026-05-19 | 1 — Scaffold | d627fbe | 13 files: scaffold, config, CLAUDE.md hierarchy, MCP config, dev skills |
| 2026-05-19 | 2 — Core Engine | 1a4a90d | 7 files: logger, session, auth_gate, reporter, tools, base_agent (ReAct loop) |
| 2026-05-19 | 3 — Threat Model | 3997800 | 8 files: mitre JSONs, STRIDE/AI skills, threat_model prompt, agent, report template |
| 2026-05-19 | 4 — Code Review | (pending) | 7 files: SAST skill, prompt, agent, semgrep/bandit/trufflehog wrappers, report template |
