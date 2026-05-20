# Skill: Add Agent

Scaffolds a new ARGUS sub-agent following all project conventions.

## Inputs
- `agent_name`: snake_case (e.g. `cloud_pentest`)
- `description`: one-line description of what this agent does
- `methodology`: which framework (PTES, OWASP, ATT&CK, STRIDE, custom)

## Process
1. Create `agents/<agent_name>.py` extending `BaseAgent`
   - Implement `async def run(target, scope, session) -> List[Finding]`
   - Load skill file: `Path(f"skills/{agent_name}/SKILL.md").read_text()`
   - Use `self._think()` → `self._act()` → `self._analyze()` loop
2. Create `skills/<agent_name>/SKILL.md` with full methodology
   - Phases, tools per phase, guardrails, confidence rules
3. Create `prompts/<agent_name>.md` with Claude system prompt
   - Persona, constraints, output format, anti-hallucination rules
4. Register in `orchestrator.py` AGENTS dict and menu
5. Add test fixture directory `tests/fixtures/<agent_name>/`
6. Add minimal test in `tests/test_agents.py`

## Guardrails
- Never skip auth_gate integration — call `require_authorization()` at agent start
- Must call `Finding.validate()` on every finding before returning
- System prompt must include: "You are a senior [role]. Think before acting."
