# Skill: ARGUS — Launch Security Intelligence Platform

When the user types `/ARGUS`, display the menu below and ask which module they want to run. Then execute the appropriate action.

## Display This Menu

```
╔══════════════════════════════════════════════════╗
║         A R G U S  Security Intelligence         ║
║    Autonomous Reconnaissance & General-purpose   ║
║         Universal Security System  v1.0          ║
╠══════════════════════════════════════════════════╣
║  [1]  Penetration Testing   (Black/White Box)    ║
║  [2]  Bug Bounty            (Full Attack Chain)  ║
║  [3]  Red Teaming           (APT Simulation)     ║
║  [4]  AI Red Teaming        (LLM/Agent Attacks)  ║
║  [5]  Voice Red Teaming     (Voice AI Attacks)   ║
║  [6]  Threat Modeling       (STRIDE + AI/ATLAS)  ║
║  [7]  Secure Code Review    (SAST + Semantic)    ║
║  [0]  Exit                                       ║
╚══════════════════════════════════════════════════╝
```

Ask: **Which module do you want to run? (1-7)**

## On Selection

Once the user picks a module, ask for the required inputs listed below, then run ARGUS via the Bash tool:

```bash
cd /opt/Legion_Sec/argus && python main.py
```

ARGUS will take over with its interactive prompts.

Alternatively, if the user wants to run a specific agent directly (non-interactively), collect inputs and run:

```bash
cd /opt/Legion_Sec/argus && python -c "
import asyncio
from agents.<agent_module> import <AgentClass>
from shared.session import Scope, Session
from shared.auth_gate import AuthRecord
# ... setup and run
"
```

## Required Inputs Per Module

**[1] Penetration Testing**
- Target (IP, domain, or URL)
- Mode: blackbox or whitebox
- If whitebox: path to source code
- Scope (in-scope assets, exclusions)
- Authorization confirmation

**[2] Bug Bounty**
- Target URL
- Login URL + credentials (if auth required)
- Additional in-scope URLs
- Authorization confirmation

**[3] Red Teaming**
- Target organization / environment
- Campaign objective (default: "Demonstrate persistent access to crown jewels")
- Scope
- Authorization confirmation

**[4] AI Red Teaming**
- Target AI system description
- Endpoint URL (optional — blank for simulation mode)
- API key for target system (optional)
- Test categories: all / prompt_injection / jailbreak / excessive_agency / multi_agent / rag

**[5] Voice Red Teaming**
- Target description
- Phone number / SIP URI / WebSocket endpoint (optional — blank for simulation)
- System type: ivr / voice_assistant / call_center_ai / voice_auth
- Acoustic tests authorized? (requires physical access authorization)

**[6] Threat Modeling**
- System description (architecture, components, data flows)
- Does the system include AI/ML components?

**[7] Secure Code Review**
- Path to code directory
- Primary language (python / javascript / typescript / java / go / php / auto)
- Framework (Flask, Django, React, etc.)

## Guardrails to Enforce Before Running Any Module

1. Confirm the user has **explicit written authorization** to test the target
2. Confirm the target is **not a production system** unless explicitly authorized
3. For Voice module: confirm physical access authorization before enabling acoustic tests
4. Remind the user: **ARGUS logs all actions** to `data/sessions.db` — findings are saved automatically

## After Running

- Reports are saved to `reports/` as both `.md` (Markdown) and `.json`
- Show the user the report path
- Offer to summarize the findings or explain specific vulnerabilities
