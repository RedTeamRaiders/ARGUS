# Tool Wrappers

Each wrapper: raw tool output → structured JSON. Nothing else.

## Required interface
```python
from shared.logger import audit
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ToolResult:
    tool: str
    command: str
    raw_output: str
    parsed: List[dict]     # structured findings — this is what Claude sees
    error: Optional[str]
    duration_s: float

async def run(target: str, options: dict = {}) -> ToolResult:
    ...
```

## Rules
1. Always parse. Claude NEVER receives raw text output.
2. If parsing fails → return ToolResult with error set, parsed=[]. Never raise.
3. Every subprocess call MUST have a timeout (default: config.DEFAULT_TIMEOUT = 300s).
4. Log every call via `audit.tool_call()` before executing.
5. Scope-check target before executing (call `scope.contains(target)`).
6. Parsed output must match the tool's declared JSON schema.

## Adding a new wrapper
1. Create `tool_wrappers/<toolname>.py`
2. Implement `async def run(target, options) -> ToolResult`
3. Parse ALL relevant fields from output into `parsed` list
4. Add a fixture file in `tests/fixtures/<toolname>/sample_output.txt`
5. Add a unit test in `tests/test_tool_wrappers.py`
