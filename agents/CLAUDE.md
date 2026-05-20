# Agents Module

All agents extend `BaseAgent` from `base_agent.py`.

## Interface
```python
class MyAgent(BaseAgent):
    name = "my_agent"

    async def run(self, target: str, scope: Scope, session: Session) -> List[Finding]:
        ...
```

## The ReAct Loop (DO NOT bypass)
Every agent must use `self._think()` → `self._act()` → `self._analyze()` in sequence.
Never call tools directly. Never skip the think step.

```python
while not context.exhausted():
    thought  = await self._think(context)     # Sonnet/Opus
    result   = await self._act(thought)       # one tool call
    analysis = await self._analyze(result, context)  # Sonnet
    context.update(analysis)
```

## Loading skill files
```python
self.skill = Path(f"skills/{self.name}/SKILL.md").read_text()
# Include in system prompt — this is the agent's methodology
```

## Model selection per call
```python
self._think(context, model="claude-sonnet-4-6")      # default reasoning
self._think(context, model="claude-opus-4-7")         # attack chain / adversarial
self._parse(output, model="claude-haiku-4-5-20251001")  # tool output parsing
```

## Anti-scanner rules (enforced at BaseAgent)
- Never run two tools simultaneously on the same surface
- Never report without `evidence` field containing direct tool output
- Critical/High confidence requires 2+ tool confirmations
- Never cite a CVE without cve-mcp-server confirmation
- Never exceed MAX_RPS (default 30 req/min)

## Adding a new agent
1. Create `agents/<name>.py` extending BaseAgent
2. Create `skills/<name>/SKILL.md` with methodology
3. Create `prompts/<name>.md` with Claude system prompt
4. Register in `orchestrator.py` menu dict
5. Add test fixture in `tests/fixtures/<name>/`
