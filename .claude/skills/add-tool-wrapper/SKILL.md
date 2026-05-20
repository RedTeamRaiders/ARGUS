# Skill: Add Tool Wrapper

Scaffolds a new tool wrapper following ARGUS conventions.

## Inputs
- `tool_name`: name of the external tool (e.g. `dalfox`, `amass`)
- `output_format`: how the tool outputs results (text, JSON, XML, CSV)
- `category`: recon / exploitation / post-exploitation / code-analysis / crawler

## Process
1. Create `tool_wrappers/<tool_name>.py`
   - Implement `async def run(target: str, options: dict) -> ToolResult`
   - Use `asyncio.create_subprocess_exec` with timeout
   - Log with `audit.tool_call()` before execution
   - Parse ALL relevant fields from output into `parsed: List[dict]`
2. Create `tests/fixtures/<tool_name>/sample_output.txt`
   - Real sample output from the tool
3. Add unit test in `tests/test_tool_wrappers.py`
   - Test: valid output parses correctly
   - Test: invalid/empty output returns ToolResult with error, not exception

## Guardrails
- NEVER pass raw output to Claude — always parse first
- ALWAYS set subprocess timeout (config.DEFAULT_TIMEOUT)
- ALWAYS validate target is in scope before running
