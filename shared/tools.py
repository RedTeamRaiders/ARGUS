"""
Claude tool definitions — Anthropic function-calling specs for every
tool ARGUS agents can invoke. Import the list you need per agent.
"""

# ── Recon ──────────────────────────────────────────────────────────────────

NMAP_TOOL = {
    "name": "run_nmap",
    "description": "Run nmap port/service scan against a target. Returns open ports, services, versions, and NSE script results.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target":  {"type": "string", "description": "IP, CIDR, or hostname"},
            "flags":   {"type": "string", "description": "nmap flags e.g. '-sV -sC -p-'", "default": "-sV -sC --top-ports 1000"},
            "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
        },
        "required": ["target"],
    },
}

NUCLEI_TOOL = {
    "name": "run_nuclei",
    "description": "Run nuclei vulnerability scanner with specified templates against a target URL.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target":    {"type": "string", "description": "Target URL or IP"},
            "templates": {"type": "string", "description": "Template path/tags e.g. 'cves,xss,sqli'", "default": ""},
            "severity":  {"type": "string", "description": "Filter by severity: critical,high,medium,low,info", "default": ""},
        },
        "required": ["target"],
    },
}

GOBUSTER_TOOL = {
    "name": "run_gobuster",
    "description": "Brute-force directories and files on a web server.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target":    {"type": "string", "description": "Target URL"},
            "wordlist":  {"type": "string", "description": "Path to wordlist", "default": "/usr/share/seclists/Discovery/Web-Content/common.txt"},
            "extensions":{"type": "string", "description": "File extensions e.g. 'php,html,js'", "default": ""},
        },
        "required": ["target"],
    },
}

FFUF_TOOL = {
    "name": "run_ffuf",
    "description": "Fuzz web endpoints, parameters, and virtual hosts.",
    "input_schema": {
        "type": "object",
        "properties": {
            "url":       {"type": "string", "description": "URL with FUZZ keyword e.g. https://target.com/FUZZ"},
            "wordlist":  {"type": "string", "description": "Path to wordlist"},
            "mode":      {"type": "string", "description": "dir|vhost|param", "default": "dir"},
            "filters":   {"type": "string", "description": "Filter by status codes e.g. '404,403'", "default": "404"},
        },
        "required": ["url", "wordlist"],
    },
}

HTTPX_TOOL = {
    "name": "run_httpx",
    "description": "Probe a list of hosts/URLs for live HTTP services, status codes, titles, technologies.",
    "input_schema": {
        "type": "object",
        "properties": {
            "targets": {"type": "array", "items": {"type": "string"}, "description": "List of URLs or IPs to probe"},
        },
        "required": ["targets"],
    },
}

KATANA_TOOL = {
    "name": "run_katana",
    "description": "JS-aware web crawler. Discovers endpoints, forms, and parameters including from JavaScript.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target":   {"type": "string", "description": "Target URL"},
            "depth":    {"type": "integer", "description": "Crawl depth", "default": 3},
            "headless": {"type": "boolean", "description": "Use headless Chrome for JS rendering", "default": True},
        },
        "required": ["target"],
    },
}

SHODAN_TOOL = {
    "name": "shodan_search",
    "description": "Search Shodan for internet-exposed services, banners, and vulnerabilities.",
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Shodan dork query e.g. 'hostname:example.com'"},
        },
        "required": ["query"],
    },
}

CVE_LOOKUP_TOOL = {
    "name": "cve_lookup",
    "description": "Look up a CVE by ID. Returns CVSS score, description, affected products, EPSS score, and CISA KEV status.",
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {"type": "string", "description": "CVE identifier e.g. CVE-2021-44228"},
        },
        "required": ["cve_id"],
    },
}

# ── Exploitation ───────────────────────────────────────────────────────────

SQLMAP_TOOL = {
    "name": "run_sqlmap",
    "description": "Test a URL/parameter for SQL injection vulnerabilities.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target":    {"type": "string", "description": "Target URL"},
            "parameter": {"type": "string", "description": "Parameter to test e.g. 'id'", "default": ""},
            "data":      {"type": "string", "description": "POST data if applicable", "default": ""},
            "dbms":      {"type": "string", "description": "Database type hint e.g. mysql,postgres,mssql", "default": ""},
            "level":     {"type": "integer", "description": "Test level 1-5", "default": 1},
            "risk":      {"type": "integer", "description": "Risk level 1-3", "default": 1},
        },
        "required": ["target"],
    },
}

DALFOX_TOOL = {
    "name": "run_dalfox",
    "description": "Test for XSS vulnerabilities. Detects reflected, stored, DOM-based XSS with context awareness.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target":   {"type": "string", "description": "Target URL"},
            "mode":     {"type": "string", "description": "url|pipe|file", "default": "url"},
            "blind":    {"type": "string", "description": "Blind XSS callback URL if testing for blind XSS", "default": ""},
            "headers":  {"type": "object", "description": "Custom headers as key-value pairs", "default": {}},
        },
        "required": ["target"],
    },
}

HYDRA_TOOL = {
    "name": "run_hydra",
    "description": "Brute-force credentials against a service (SSH, FTP, HTTP, SMB, etc.).",
    "input_schema": {
        "type": "object",
        "properties": {
            "target":   {"type": "string", "description": "Target IP or hostname"},
            "service":  {"type": "string", "description": "Service: ssh|ftp|http-post-form|smb|rdp"},
            "userlist": {"type": "string", "description": "Path to username list"},
            "passlist": {"type": "string", "description": "Path to password list"},
            "username": {"type": "string", "description": "Single username (use instead of userlist)", "default": ""},
        },
        "required": ["target", "service"],
    },
}

MSF_EXPLOIT_TOOL = {
    "name": "run_msf_exploit",
    "description": "Execute a Metasploit exploit module against a target.",
    "input_schema": {
        "type": "object",
        "properties": {
            "module":  {"type": "string", "description": "Metasploit module path e.g. exploit/multi/handler"},
            "options": {"type": "object", "description": "Module options as key-value pairs e.g. {RHOSTS: '10.10.10.1', LHOST: '10.10.14.5'}"},
            "payload": {"type": "string", "description": "Payload module path", "default": ""},
        },
        "required": ["module", "options"],
    },
}

# ── Post-Exploitation ──────────────────────────────────────────────────────

LINPEAS_TOOL = {
    "name": "run_linpeas",
    "description": "Run linPEAS on a remote Linux host via an active session to enumerate privilege escalation vectors.",
    "input_schema": {
        "type": "object",
        "properties": {
            "session_id": {"type": "string", "description": "Active shell session ID"},
        },
        "required": ["session_id"],
    },
}

BLOODHOUND_TOOL = {
    "name": "bloodhound_query",
    "description": "Query BloodHound for Active Directory attack paths and domain information.",
    "input_schema": {
        "type": "object",
        "properties": {
            "query":    {"type": "string", "description": "Natural language query e.g. 'shortest path to Domain Admins'"},
            "cypher":   {"type": "string", "description": "Raw Cypher query (optional, overrides natural language)", "default": ""},
        },
        "required": ["query"],
    },
}

# ── Code Analysis ──────────────────────────────────────────────────────────

SEMGREP_TOOL = {
    "name": "run_semgrep",
    "description": "Run Semgrep SAST on a codebase or file. Returns security findings with CWE mapping.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path":    {"type": "string", "description": "File or directory path to scan"},
            "ruleset": {"type": "string", "description": "Semgrep ruleset e.g. 'p/security-audit'", "default": "p/security-audit"},
        },
        "required": ["path"],
    },
}

BANDIT_TOOL = {
    "name": "run_bandit",
    "description": "Run Bandit Python security linter on a file or directory.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path":     {"type": "string", "description": "File or directory to scan"},
            "severity": {"type": "string", "description": "Minimum severity: LOW|MEDIUM|HIGH", "default": "LOW"},
        },
        "required": ["path"],
    },
}

# ── Tool groups per agent ──────────────────────────────────────────────────

PENTEST_TOOLS    = [NMAP_TOOL, NUCLEI_TOOL, GOBUSTER_TOOL, FFUF_TOOL, HTTPX_TOOL,
                    KATANA_TOOL, SHODAN_TOOL, CVE_LOOKUP_TOOL, SQLMAP_TOOL, DALFOX_TOOL,
                    HYDRA_TOOL, MSF_EXPLOIT_TOOL, LINPEAS_TOOL, BLOODHOUND_TOOL]

BUG_BOUNTY_TOOLS = [NMAP_TOOL, NUCLEI_TOOL, GOBUSTER_TOOL, FFUF_TOOL, HTTPX_TOOL,
                    KATANA_TOOL, SHODAN_TOOL, CVE_LOOKUP_TOOL, SQLMAP_TOOL, DALFOX_TOOL]

RED_TEAM_TOOLS   = [NMAP_TOOL, MSF_EXPLOIT_TOOL, LINPEAS_TOOL, BLOODHOUND_TOOL,
                    HYDRA_TOOL, CVE_LOOKUP_TOOL]

CODE_REVIEW_TOOLS = [SEMGREP_TOOL, BANDIT_TOOL]

THREAT_MODEL_TOOLS = [CVE_LOOKUP_TOOL, SHODAN_TOOL]
