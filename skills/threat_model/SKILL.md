# Skill: Threat Model — STRIDE + PASTA + DREAD

## Purpose
Systematically identify, analyze, and prioritize security threats in a given system.
Think like an attacker who understands the architecture — not like an auditor running a checklist.

## Inputs Required
- System description OR architecture diagram text OR data flow description
- System type: web app / API / mobile / desktop / cloud / on-premise / hybrid
- Known technologies: languages, frameworks, databases, auth mechanisms
- Crown jewels: what data/functionality is most valuable to protect?
- User roles: who are the different actors in the system?

## Methodology

### Phase 1 — Asset Identification
Before identifying threats, identify what's worth protecting:

**Data assets:**
- PII, financial data, health records, credentials, IP, secrets/keys
- Data at rest (databases, files, backups)
- Data in transit (APIs, message queues, network traffic)
- Data in use (memory, caches, session state)

**System assets:**
- Authentication and authorization systems
- Payment processing components
- Admin panels and privileged interfaces
- Third-party integrations and APIs
- CI/CD pipelines and deployment infrastructure

**Crown jewel identification:**
Ask: "If an attacker compromised ONE component, what would be the highest impact?"
That component is the primary threat modeling target.

### Phase 2 — Trust Boundary Mapping
Identify where data crosses trust levels:
- Internet ↔ DMZ
- DMZ ↔ Internal network
- User ↔ Application
- Application ↔ Database
- Application ↔ Third-party service
- Container ↔ Host
- Microservice ↔ Microservice

Each boundary is an attack surface. Map the data flows across each.

### Phase 3 — STRIDE Analysis (per component and per boundary)

For EVERY component and data flow, apply STRIDE:

**S — Spoofing (Authentication)**
- Can an attacker impersonate a user, service, or component?
- Is identity validated at every trust boundary?
- Are tokens/credentials properly protected?
- Test angles: credential theft, token forgery, session fixation, replay attacks

**T — Tampering (Integrity)**
- Can data be modified in transit or at rest without detection?
- Are inputs validated server-side?
- Are database writes authorized and logged?
- Test angles: parameter tampering, SQL injection, MITM, log manipulation

**R — Repudiation (Non-repudiation)**
- Can users deny performing an action?
- Are audit logs complete, tamper-proof, and monitored?
- Are transactions signed or timestamped?
- Test angles: log deletion, unsigned transactions, missing audit trails

**I — Information Disclosure (Confidentiality)**
- What sensitive data can an unauthorized user access?
- Are error messages revealing internal details?
- Is data encrypted at rest and in transit?
- Test angles: IDOR, over-permissive APIs, verbose errors, path traversal, insecure direct references

**D — Denial of Service (Availability)**
- Can an attacker make the system unavailable?
- Are there rate limits and resource quotas?
- Are there single points of failure?
- Test angles: resource exhaustion, large payloads, recursive calls, missing rate limits

**E — Elevation of Privilege (Authorization)**
- Can a lower-privileged user gain higher-privileged access?
- Is authorization checked on every request (not just at login)?
- Are admin functions properly protected?
- Test angles: IDOR, broken access control, JWT manipulation, privilege escalation paths

### Phase 4 — Attack Tree Generation
For the top 3-5 threats identified, build attack trees:

```
Goal: [attacker's objective]
├── Attack Path 1
│   ├── Prerequisite A
│   │   └── Sub-step a1
│   └── Prerequisite B
└── Attack Path 2
    └── Prerequisite C
```

Rate each path: Likelihood (H/M/L) × Impact (H/M/L) = Risk

### Phase 5 — DREAD Scoring
For each threat:

| Factor | Score (1-10) | Description |
|---|---|---|
| Damage | | How bad if exploited? |
| Reproducibility | | How easy to reproduce? |
| Exploitability | | How easy to exploit? |
| Affected Users | | How many users impacted? |
| Discoverability | | How easy to discover? |

DREAD Score = Average of all 5 factors
Priority: ≥8 Critical, 6-7 High, 4-5 Medium, <4 Low

### Phase 6 — PASTA Validation (Process for Attack Simulation and Threat Analysis)
Stage 1: Define business objectives
Stage 2: Define technical scope
Stage 3: Decompose application (DFD)
Stage 4: Threat analysis (threat intelligence)
Stage 5: Vulnerability and weakness analysis
Stage 6: Attack modeling (simulate attack scenarios)
Stage 7: Risk/impact analysis and prioritization

### Phase 7 — Mitigations and Controls
For each threat, provide:
- Preventive control (stops the attack)
- Detective control (detects if it happens)
- Corrective control (recovers after incident)
- MITRE ATT&CK technique(s) the threat maps to

## Output Format
Produce: threat matrix + attack trees + DREAD scores + control recommendations + ATT&CK heatmap

## Guardrails
- Never speculate about threats without architectural basis
- Always map threats to specific components or data flows
- Score conservatively — high scores require clear justification
- Distinguish confirmed design flaws from theoretical threats
