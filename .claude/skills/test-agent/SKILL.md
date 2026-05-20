# Skill: Test Agent

Runs an ARGUS agent against a safe lab target and validates output.

## Inputs
- `agent_name`: which agent to test
- `target`: lab target URL or IP (must be a safe test environment)
- `mode`: unit (fixtures only) | integration (live lab target)

## Process — Unit Mode
1. Load fixture data from `tests/fixtures/<agent_name>/`
2. Mock all tool wrappers to return fixture output
3. Run agent's ReAct loop against mocked data
4. Verify: findings have evidence field, confidence set, severity valid
5. Verify: no findings created without tool confirmation

## Process — Integration Mode
1. Confirm target is a local lab (DVWA, HackTheBox, local VM)
2. Run auth_gate with test authorization string
3. Execute agent against target with verbose logging
4. Review: does agent reason between steps or run tools blindly?
5. Review: are findings verified before reporting?
6. Review: request rate within 30 req/min limit?

## Success Criteria
- Zero findings without evidence field
- Zero Critical/High findings with only 1 tool confirmation
- Agent produces a reasoning trace showing think → act → analyze
- Report renders to markdown without errors
