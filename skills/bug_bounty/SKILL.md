# Skill: Bug Bounty — Full Attack Chain (OSCP/OSWE-Style)

## Purpose
Exploit web applications end-to-end like an OSCP/OSWE candidate: full recon → enumeration → exploitation → chaining → impact demonstration. Not just finding individual vulnerabilities — finding the highest-impact chain and proving it.

Reference: PTES, OWASP Testing Guide v4.2, PortSwigger Web Security Academy, HackerOne Disclosure Database.

## The Bug Bounty Mindset

Think like an attacker who wants ONE high-impact finding, not 10 low-quality ones:
1. **Crown jewels first**: what does the app protect? (PII, financial data, admin access, user accounts)
2. **What's the blast radius?** A stored XSS on the admin panel is worth more than reflected XSS on a public page
3. **Chain always beats single finding**: SSRF + metadata access > SSRF alone
4. **Confirm before escalating**: don't build a chain on an unconfirmed primitive
5. **Demonstrate impact**: show exfiltration, account takeover, or data modification — not just "potential"

## Phase 1 — Passive Recon (No Active Scanning)

**Target intelligence gathering:**
- WHOIS, DNS records (A, MX, TXT, CNAME, NS)
- Subdomain enumeration: passive (cert.sh, Shodan, VirusTotal) before active
- Historical URLs: Wayback Machine (gau) — look for deprecated endpoints, old params
- JavaScript files: linkfinder → hidden API endpoints, internal routes, hardcoded tokens
- GitHub/GitLab: leaked keys, internal documentation, old commits
- Shodan: open ports, exposed services, infrastructure details
- Technology fingerprinting: Wappalyzer equivalent, response headers, error messages

**Questions to answer before touching the target:**
- What technologies? (WAF, framework, CDN, auth provider)
- What is the attack surface? (login, registration, API, file upload, admin, webhooks)
- Any obvious low-hanging fruit? (exposed admin panels, debug endpoints, test credentials)

## Phase 2 — Active Recon (One Tool at a Time)

**Port + service enumeration:**
- nmap: `-sV -sC` on in-scope IP ranges (not aggressive, no -A)
- httpx: probe all discovered URLs for status codes, titles, tech headers
- nuclei: detect-only scan (detection templates only, no exploitation yet)

**Web application mapping:**
- katana: crawl application structure (no payloads — mapping only)
- gobuster/ffuf: directory + file brute force (common.txt → raft-large → custom wordlists)
- Manual browsing: register account, explore all features as regular user

**API discovery:**
- Swagger/OpenAPI docs: `/api/docs`, `/swagger`, `/api/v1/swagger.json`
- JavaScript analysis: extract API calls from JS bundles
- HTTP history: proxy all traffic through BurpSuite-equivalent

## Phase 3 — Vulnerability Identification

Work through each attack surface systematically. Start with what's MOST LIKELY to yield high impact:

**High-Impact Targets (always test these first):**

1. **Authentication endpoints** (login, registration, password reset, 2FA):
   - Username enumeration via timing or error differences
   - Brute force protection bypass (rate limit bypass, account lockout logic)
   - Password reset flaws: token predictability, token reuse, host header injection
   - OAuth: redirect_uri bypass, state param missing, implicit flow token leakage
   - JWT: none algorithm, algorithm confusion, weak secret, missing expiry

2. **File upload endpoints**:
   - Upload PHP/JSP/ASP shell disguised as image
   - Path traversal in filename: `../../web/shell.php`
   - SSRF via file content (SVG with external entity, PDF with URL)
   - Stored XSS via SVG upload

3. **Account/profile endpoints**:
   - IDOR: change user IDs in requests to access other accounts
   - Mass assignment: extra fields accepted by API (role, admin, verified)
   - Horizontal/vertical privilege escalation

4. **Admin functionality**:
   - Exposed without authentication
   - Accessible to regular users
   - Broken function-level access control

**Medium-Impact Targets:**

5. **Search/query parameters** → SQLi, SSTI, XSS reflected
6. **Comment/post fields** → Stored XSS
7. **Import/export features** → XXE, CSV injection, SSRF
8. **Webhooks/callback URLs** → SSRF
9. **PDF/report generation** → SSRF, HTML injection
10. **API rate limiting** → Brute force, enumeration

## Phase 4 — Exploitation

**SQL Injection:**
- Confirm: add `'` → error, `''` → normal, `'--` → normal = likely injectable
- sqlmap only after manual confirmation of injectable parameter
- Always test for blind/time-based if error-based fails
- Goal: dump admin credentials, not just prove injection

**XSS — The Full Pipeline:**
1. Inject canary token → which params reflect?
2. Determine injection context (HTML body, attribute, JS, CSS, template)
3. Select context-appropriate payload (from xss_reflected.json knowledge base)
4. Inject → monitor for execution (Playwright)
5. If stored: visit admin panel, moderation queue, export pages
6. Impact: steal admin cookie, perform CSRF as admin, exfiltrate data

**SSRF:**
1. Find URL/endpoint parameters
2. Probe internal: `http://127.0.0.1/`, `http://169.254.169.254/latest/meta-data/`
3. Try protocol confusion: `http://`, `https://`, `file://`, `dict://`, `gopher://`
4. On cloud: try IMDSv1 vs IMDSv2, check role ARNs in metadata
5. Impact: cloud credentials exfiltration, internal service access

**Authentication bypass:**
1. Try null/empty values, SQL injection in login
2. OAuth flow manipulation
3. JWT algorithm confusion attack
4. Password reset race condition

## Phase 5 — Post-Exploitation & Chaining

Think: "I have X — what does X enable?"

**Common chains:**
- XSS (admin panel) → CSRF to add attacker as admin
- IDOR + Mass Assignment → account takeover
- SSRF → internal API → admin action
- SQLi → credential dump → auth bypass → admin access
- File upload → RCE → data exfiltration
- Subdomain takeover → cookie theft → session hijack

**Demonstrate impact (for maximum severity):**
- Account takeover: log in as another user (use a test account)
- Data exfiltration: show what data is accessible (redact PII in report)
- Admin access: show admin panel without credentials
- RCE: execute `id`, `whoami`, `ls /etc` (never destructive commands)

## Phase 6 — Evidence & Reporting

**Every finding needs:**
- HTTP request that triggers the vulnerability (exact headers, body)
- HTTP response showing the vulnerability
- Screenshot of impact (XSS alert, admin panel, data exposure)
- HAR file if injection happened through Playwright
- Reproduction steps (numbered, specific, not vague)
- Impact assessment (what an attacker gains, business impact)
- CVSS score with vector string

**Severity guidelines for bug bounty programs:**
| Severity | Example |
|----------|---------|
| Critical | RCE, SQLi leading to data dump, account takeover at scale |
| High | IDOR on sensitive data, auth bypass, stored XSS on admin panel |
| Medium | Reflected XSS, CSRF on sensitive action, broken access control (limited impact) |
| Low | Open redirect, info disclosure (non-sensitive), self-XSS |
| Informational | Best practice violations, missing headers |

## Guardrails
- Never test beyond defined scope
- Never use destructive payloads (drop table, rm -rf, format disk)
- Never access real PII — use test accounts
- Always confirm primitive before building chain
- Never report without Playwright or tool-confirmed evidence
