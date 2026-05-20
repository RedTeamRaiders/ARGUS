# ARGUS — Autonomous Reconnaissance & General-purpose Universal Security System

AI-powered security agent that behaves like a human pentester, not a DAST scanner. Built on Claude's ReAct (Reason + Act) loop — Claude reasons between every action, choosing tools like a senior penetration tester would.

> **Legal notice:** For authorized security testing only. You are responsible for ensuring you have explicit written authorization before testing any target. Unauthorized use is illegal.

---

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | Penetration Testing | Black box + white box, full compromise chain |
| 2 | Bug Bounty | OSCP/OSWE-style web application testing |
| 3 | Red Teaming | APT simulation + MITRE ATT&CK coverage |
| 4 | AI Red Teaming | OWASP LLM Top 10 + MITRE ATLAS + agentic AI attacks |
| 5 | Voice Red Teaming | IVR bypass + voice biometric + acoustic attacks |
| 6 | Threat Modeling | STRIDE + PASTA + AI/ATLAS scenarios |
| 7 | Secure Code Review | SAST + semantic analysis + CWE mapping |

---

## Requirements

- Python 3.11+
- [nmap](https://nmap.org/download.html)
- [Anthropic API key](https://console.anthropic.com/settings/keys) (Claude Haiku 4.5 / Sonnet 4.6 / Opus 4.7)

Optional (enables additional modules):
- Metasploit Framework (red teaming / exploitation)
- OWASP ZAP (web scanning)
- BloodHound + Neo4j (AD enumeration)
- Shodan, VirusTotal, Censys, SecurityTrails API keys (OSINT)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/RedTeamRaiders/ARGUS.git
cd ARGUS
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Playwright browsers (required for XSS verification)

```bash
playwright install chromium
```

### 5. Configure your API keys

```bash
cp .env.example .env
```

Open `.env` and set at minimum:

```env
ANTHROPIC_API_KEY=sk-ant-api03-...    # required — get from console.anthropic.com
```

Add any other keys for the tools you want to use (Shodan, VirusTotal, etc.).

> **Important:** Never commit `.env` — it is in `.gitignore` and must stay there.

### 6. Verify setup

```bash
python main.py
```

You should see the ARGUS banner and module menu. If the API key check fails, confirm your `ANTHROPIC_API_KEY` is set correctly in `.env`.

---

## Usage

### Interactive menu

```bash
python main.py
```

Select a module (1–7), provide the target and authorization details, and ARGUS runs the full engagement.

### Run a single agent directly

```bash
python -m agents.pentest       # penetration testing
python -m agents.bug_bounty    # bug bounty
python -m agents.red_team      # red teaming
python -m agents.ai_redteam    # AI red teaming
python -m agents.voice_redteam # voice red teaming
python -m agents.threat_model  # threat modeling
python -m agents.code_review   # secure code review
```

### Run tests

```bash
pytest tests/
```

---

## Configuration

All settings are in `.env`. Key options:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | **Required.** Your Anthropic API key |
| `ARGUS_MAX_RPS` | `30` | Max requests/min — keeps traffic looking human |
| `ARGUS_DEFAULT_TIMEOUT` | `300` | Tool execution timeout in seconds |
| `ARGUS_LOG_LEVEL` | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`) |
| `ARGUS_TRUSTED_OPERATOR` | `0` | Set to `1` to skip the authorization statement prompt |

---

## Architecture

```
ARGUS/
├── main.py              # Entry point — dependency + API key check, menu
├── orchestrator.py      # Routes menu selections to agents, manages sessions
├── config.py            # All config loaded from .env
│
├── agents/              # 7 sub-agents, each with a ReAct loop
│   ├── base_agent.py    # Think → Act → Analyze loop all agents extend
│   ├── pentest.py
│   ├── bug_bounty.py
│   ├── red_team.py
│   ├── ai_redteam.py
│   ├── voice_redteam.py
│   ├── threat_model.py
│   └── code_review.py
│
├── tool_wrappers/       # Raw tool output → structured JSON only
│   ├── nmap.py
│   ├── sqlmap.py
│   ├── nuclei.py
│   ├── gobuster.py
│   ├── ffuf.py
│   ├── hydra.py
│   ├── semgrep.py
│   └── ...              # 18 wrappers total
│
├── shared/              # Core infrastructure
│   ├── auth_gate.py     # Authorization enforcement (runs before every agent)
│   ├── session.py       # SQLite-backed session + finding store
│   ├── reporter.py      # Unified finding schema + Markdown/JSON report renderer
│   └── logger.py        # Append-only JSON-lines audit trail
│
├── skills/              # Methodology files loaded into agent system prompts
├── prompts/             # Claude system prompts per agent
├── templates/           # Report templates
└── data/                # sessions.db, payload knowledge (gitignored)
```

### Models used

| Model | Used for |
|-------|----------|
| `claude-haiku-4-5` | Tool output parsing, deduplication, classification |
| `claude-sonnet-4-6` | Agent reasoning, STRIDE/ATT&CK mapping, report writing |
| `claude-opus-4-7` | Attack chain construction, adversarial reasoning, AI threat modeling |

---

## Output

Reports are saved to `reports/` after each engagement:

```
reports/
├── 20260520_143200_pentest_demo_testfire_net.md    # Markdown report
└── 20260520_143200_pentest_demo_testfire_net.json  # Machine-readable JSON
```

The JSON format follows the unified finding schema in `shared/reporter.py` — every finding includes severity, CVSS score, CVSS vector, CWE, MITRE ATT&CK mapping, evidence (direct tool output), PoC, and remediation.

Audit logs are written to `.claude/audit.log` as JSON lines — every tool call, Claude call, and finding is timestamped.

---

## Security rules enforced by ARGUS

1. `shared/auth_gate.py` runs before any agent — no exceptions
2. Every finding must have an `evidence` field containing direct tool output
3. Tool wrappers return structured JSON only — Claude never receives raw text
4. Critical/High findings require 2+ independent tool confirmations
5. XSS findings require Playwright headless verification before reporting
6. Max 30 req/min by default — traffic looks human, not scanner-shaped
7. Every action is logged to the audit trail

---

## Contributing

1. Fork the repo and create a feature branch
2. Read `agents/CLAUDE.md` before editing any agent
3. Read `tool_wrappers/CLAUDE.md` before editing any tool wrapper
4. Run `pytest tests/` — all tests must pass before opening a PR
5. Never commit `.env`, `data/sessions.db`, or `.claude/settings.local.json`

---

## License

For authorized security testing only. See `LICENSE` for terms.
