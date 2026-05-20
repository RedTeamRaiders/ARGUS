# Shared Module

Core infrastructure used by all agents.

## auth_gate.py
MUST be called before any active agent runs. Collects target, scope, authorization.
```python
from shared.auth_gate import require_authorization
scope = await require_authorization()  # raises if user doesn't confirm
```

## session.py
SQLite-backed session store. Persists findings, tool outputs, mental model state.
```python
session = await Session.create(target, scope)
await session.add_finding(finding)
await session.update_context(key, value)
state = await session.get_state()
```

## reporter.py
Unified Finding schema. Every agent writes findings in this format.
```python
Finding(
    agent="pentest",
    title="SQL Injection in /api/users",
    severity="High",
    cvss_score=8.1,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cwe="CWE-89",
    cve=None,
    mitre_attack=["T1190"],
    owasp="A03",
    description="...",
    evidence="sqlmap output: ...",     # MANDATORY — direct tool output
    observed="...",                    # tool facts only
    inferred="...",                    # Claude reasoning
    poc="curl -X POST ...",
    impact="...",
    remediation="...",
    confidence="High",                 # High/Medium/Low
    confirmed=True,                    # False until 2+ tools confirm
)
```

## logger.py
Audit trail. Every tool call, every Claude call, every finding — timestamped.
```python
from shared.logger import audit
audit.tool_call(tool="nmap", command="nmap -sV 10.10.10.1", agent="pentest")
audit.finding(finding)
audit.claude_call(model=..., tokens_in=..., tokens_out=...)
```

## tools.py
Claude tool definitions for MCP tool use. Import the tool spec you need.
