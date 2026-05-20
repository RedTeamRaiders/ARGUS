# Skill: Secure Code Review — SAST + Semantic + CWE Mapping

## Purpose
Identify security vulnerabilities in source code through static analysis and deep semantic reasoning.
Think like an attacker who reads code — not like a linter running pattern rules.

Reference: OWASP Code Review Guide v2, CWE Top 25, SANS Top 25, MITRE ATT&CK (technique implementations).

## Inputs Required
- Source code (files, repository, or code snippets)
- Language(s): Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C/C++, etc.
- Framework(s): Django, Flask, Express, Spring, Rails, Laravel, etc.
- Entry points: web routes, CLI args, API handlers, message consumers
- Authentication mechanism: session, JWT, OAuth, API keys
- Data sensitivity: PII, financial, health, credentials, IP

## Methodology

### Phase 1 — Attack Surface Mapping
Before looking for vulnerabilities, map where untrusted data enters the system:

**Entry points (where attacker-controlled data arrives):**
- HTTP request: URL params, query strings, body (JSON/form), headers, cookies, files
- WebSocket messages
- CLI arguments and environment variables
- Database reads (if DB is shared/compromised upstream)
- Third-party API responses
- File reads (config, uploads, imports)
- IPC: message queues, pipes, shared memory

**Sinks (where data causes harm):**
- SQL/NoSQL queries → SQLi
- Shell commands, subprocess calls → Command injection
- HTML/JS output → XSS
- File system paths → Path traversal, arbitrary write
- HTTP requests constructed from input → SSRF
- Template engines → SSTI
- Deserialization calls → RCE
- Eval/exec/compile → Code injection
- Cryptographic operations → Weak crypto
- Auth checks → AuthN/AuthZ bypass

### Phase 2 — Data Flow Tracing
For each entry point, trace data flow to sinks:
1. Does the data reach a dangerous sink?
2. Is it sanitized/validated before the sink?
3. Is the sanitization bypassable (encoding tricks, type confusion, partial match)?
4. Are there indirect paths (stored in DB, read back later)?

### Phase 3 — Vulnerability Classes (check ALL for each entry point)

**Injection**
- SQL injection: string concatenation in queries, ORM raw() calls, stored procedures
- Command injection: os.system, subprocess without shell=False, exec(), eval()
- SSTI: template.render(user_input), Jinja2/Twig/FreeMarker with untrusted data
- LDAP injection: directory queries with user input
- XML/XXE: XML parsers with untrusted input, ENTITY expansion enabled
- XPath injection: XPath queries with user data

**Broken Authentication**
- Hardcoded credentials (passwords, API keys, tokens in source)
- Weak password policy enforcement
- Missing rate limiting on auth endpoints
- Insecure session management (predictable tokens, long expiry, no invalidation)
- JWT: algorithm confusion (none/HS256 confusion), weak secret, no expiry check
- OAuth: redirect_uri not validated, state parameter missing, token leakage in logs

**Broken Access Control**
- IDOR: object references without ownership check (user_id from request used directly)
- Privilege escalation: role checks missing or bypassable
- Path traversal: `../` in file operations, zip slip
- Mass assignment: ORM models accepting all request fields
- Forced browsing: admin endpoints accessible without auth
- CORS misconfiguration: wildcard or reflecting origin without credentials flag check

**Cryptographic Failures**
- Sensitive data in plaintext (passwords, PII, keys logged or stored unencrypted)
- Weak algorithms: MD5/SHA1 for passwords, ECB mode, DES/3DES
- Hardcoded secrets, IVs, or salts
- Insufficient key derivation (PBKDF2/bcrypt/argon2 with too few iterations)
- Predictable random: `random` instead of `secrets`, `Math.random()` for security
- Insecure TLS: certificate validation disabled, outdated protocol/cipher

**Security Misconfiguration**
- Debug mode enabled in production configs
- Stack traces / verbose errors exposed to users
- Default credentials in config files
- Unnecessary features/endpoints enabled
- Missing security headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options

**Vulnerable Components**
- Outdated dependencies with known CVEs
- Insecure deserialization: pickle, yaml.load, JSON with custom object_hook
- Prototype pollution (JavaScript): recursive merge, lodash.merge with user input
- XML parsers with XXE enabled

**Insecure Design**
- Business logic flaws: negative quantities, integer overflow in financial calc
- Race conditions: TOCTOU, non-atomic operations on shared state
- Insecure direct references to internal resources
- Missing function-level access control
- Sensitive data in URL parameters (logs, referrer headers)

**Logging and Monitoring**
- Sensitive data in logs (passwords, tokens, PII)
- Missing audit trail for security-relevant actions
- Log injection: user input written to logs without sanitization

**SSRF**
- User-controlled URLs passed to HTTP clients
- Internal metadata endpoints (169.254.169.254, fd00:ec2::254)
- DNS rebinding exposure
- URL scheme confusion: file://, gopher://, dict://

**Insecure File Handling**
- Unrestricted file upload (no type/size/content validation)
- Serving uploaded files from web root
- Path traversal in file download endpoints
- Zip slip: extract archives without path normalization

### Phase 4 — Language-Specific Checks

**Python**
- `eval()`, `exec()`, `compile()` with user data
- `pickle.loads()`, `yaml.load()` (use yaml.safe_load)
- `subprocess` with `shell=True`
- `os.system()`, `os.popen()`
- Django: raw SQL with `cursor.execute(f"...")`, `extra(where=[user_input])`
- Flask: `render_template_string(user_input)` → SSTI
- Jinja2: `Environment(undefined=Undefined)` with auto-escape off

**JavaScript / TypeScript**
- `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- `innerHTML`, `outerHTML`, `document.write()` with user data → XSS
- `dangerouslySetInnerHTML` in React
- `child_process.exec(userInput)` without sanitization
- Prototype pollution: `Object.assign({}, userInput)` without prototype check
- `JSON.parse()` with reviver that executes code
- Insecure `postMessage` handler (no origin check)

**Java**
- `Runtime.exec()`, `ProcessBuilder` with user input
- XMLDecoder, Java native deserialization (ObjectInputStream)
- JNDI lookup with user-controlled string → Log4Shell pattern
- Spring: `@Value` injection, SpEL expression with user data
- OGNL injection (Struts, FreeMarker)

**Go**
- `os/exec` with shell expansion
- SQL: `db.Query(fmt.Sprintf("... %s", userInput))`
- `html/template` vs `text/template` confusion (auto-escape bypassed)
- `crypto/rand` vs `math/rand` for security tokens

**PHP**
- `eval()`, `assert()`, `preg_replace('/e')` with user data
- `system()`, `exec()`, `shell_exec()`, backtick operator
- `include`/`require` with user-controlled path → LFI/RFI
- `unserialize()` with user data
- `$_GET/$_POST` passed directly to SQL queries

### Phase 5 — Secrets Detection
Scan for hardcoded secrets (complement semgrep + TruffleHog with semantic analysis):
- Passwords in config objects, dict literals, default parameter values
- API keys matching patterns (sk-, AKIA, ghp_, xox, ya29.)
- Private keys (BEGIN RSA/EC/PEM PRIVATE KEY)
- Connection strings with embedded credentials
- Tokens in test fixtures that are real values
- Secrets in comments ("# TODO: remove this key in prod")
- Base64-encoded credentials

### Phase 6 — Dependency Analysis
- Map all `import`/`require`/`use` to packages
- Flag packages with known CVEs (semgrep + bandit provide this)
- Flag outdated lock files
- Flag packages pulled from non-standard sources (git URLs, local paths)
- Flag dev dependencies promoted to production

## Severity Assignment

Use CWE + exploitability to assign severity:

| Severity | Criteria |
|----------|----------|
| Critical | RCE, auth bypass, mass data exfiltration — direct, no user interaction |
| High | SQLi, stored XSS, SSRF to internal, IDOR on sensitive data, hardcoded creds |
| Medium | Reflected XSS, CSRF on sensitive actions, path traversal (read only), weak crypto |
| Low | Verbose errors, missing headers, low-impact info disclosure |
| Info | Best practice violations, dead code, style issues |

## Output Format

For each finding:
- **CWE ID** and name
- **File + line number** (exact, not approximate)
- **Vulnerable code snippet** (exact lines from source)
- **Attack scenario** (how an attacker exploits this)
- **Proof-of-concept** (payload or request that triggers the issue)
- **Impact** (what the attacker gains)
- **Remediation** (specific code fix, not generic advice)
- **MITRE ATT&CK** technique (if applicable)
- **Confidence** (High/Medium/Low) + reasoning

## Guardrails
- Never report a finding without the exact file:line reference
- Never report a theoretical vulnerability without a realistic attack path
- Distinguish: confirmed code flaw vs. potential issue requiring runtime context
- Auto-tools (semgrep/bandit) produce false positives — validate every finding semantically
- Secrets scan: verify the pattern matches a real secret format, not a placeholder/example
- Rate severity honestly — not every SQLi is Critical if the data is non-sensitive
