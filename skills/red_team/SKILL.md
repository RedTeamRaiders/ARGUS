# Skill: Red Team — APT Simulation + MITRE ATT&CK

## Purpose
Simulate a sophisticated, persistent adversary (APT) targeting a specific organization. Unlike pentesting (find vulns), red teaming tests whether the organization can DETECT and RESPOND to a real attacker. The mission: achieve a specific objective (data exfiltration, persistent access, domain compromise) while evading detection for as long as possible.

Reference: MITRE ATT&CK Enterprise v14, TIBER-EU framework, CBEST, US CREST Red Team framework.

## The Red Team Mindset

**You are an APT, not a penetration tester:**
- **Stealthy over loud**: a quiet compromise that persists undetected for 30 days > a loud compromise that triggers EDR in 10 minutes
- **Goal-oriented**: you have a specific objective (exfiltrate HR data, gain persistent domain access, compromise CEO email)
- **Realistic TTPs**: use techniques a real APT would use, not just whatever achieves access fastest
- **Test the whole defense**: EDR, SIEM, SOC response, email gateway, endpoint detection, network monitoring
- **Minimize footprint**: every artifact left is a detection opportunity

## MITRE ATT&CK Campaign Planning

Plan each campaign by ATT&CK phase:

### TA0043 — Reconnaissance
- OSINT: LinkedIn (employee mapping), job postings (tech stack), GitHub (leaked configs, repos)
- Passive DNS, certificate transparency logs
- Shodan/Censys for external attack surface
- Social engineering intelligence gathering

### TA0042 — Resource Development
- Infrastructure: C2 servers, redirectors, domain fronting
- Tooling: avoid flagged tools (Metasploit signatures); use custom or LOTL (Living Off the Land)
- Staging: hosting payloads on trusted infrastructure (GitHub, SharePoint)

### TA0001 — Initial Access
**Preferred (realistic, hard to detect):**
- Phishing (T1566): crafted email with legitimate-looking attachment or link
- Spearphishing link (T1566.002): custom landing page, drive-by compromise
- Valid accounts (T1078): credential stuffing, leaked credentials, password spray
- External-facing service exploitation (T1190): CVE in VPN, web app, email gateway

**Avoid (noisy, rarely used by APTs):**
- Brute force SSH on every IP
- Running Metasploit default modules without modification

### TA0002 — Execution
- User execution: macro documents, ISO mounting, LNK files
- Windows Management Instrumentation (T1047): lateral movement and execution
- Scheduled tasks (T1053): persistence + execution
- LOTL: PowerShell, certutil, mshta, regsvr32, rundll32

### TA0003 — Persistence
- Registry Run keys (T1547.001)
- Scheduled tasks (T1053.005)
- DLL hijacking (T1574.001)
- WMI subscriptions (T1546.003)
- Web shells (T1505.003) — for web-facing servers
- Golden/Silver tickets — for AD persistence

### TA0004 — Privilege Escalation
- Token manipulation (T1134)
- Process injection (T1055): hollowing, DLL injection
- PrintNightmare, other kernel exploits — only if stealthier options exhausted
- Abuse elevation control mechanism (T1548): UAC bypass

### TA0005 — Defense Evasion
**Critical for red team success:**
- AMSI bypass (T1562.001): reflection, memory patching
- ETW bypass: disable event tracing
- LOLBins: certutil, BITSAdmin, mshta to proxy execution
- Sign payloads with stolen/dummy cert
- Obfuscate PowerShell: Invoke-Obfuscation, AMSI bypass one-liners
- Sleep jitter in C2 beacons (mimic legitimate traffic timing)
- HTTPS C2 with domain fronting or CDN redirect
- Timestomping (T1070.006): modify file metadata
- Clear event logs (T1070.001): target Security, System, PowerShell logs

### TA0006 — Credential Access
- LSASS dump (T1003.001): Mimikatz, ProcDump + Mimikatz offline
- NTDS.dit (T1003.003): shadow copy + ntdsutil
- Kerberoasting (T1558.003): GetUserSPNs → offline crack
- AS-REP roasting (T1558.004): accounts without pre-auth
- DCSync (T1003.006): domain replication rights
- Browser credential extraction (T1555.003)

### TA0007 — Discovery
- Network share discovery (T1135)
- Domain trust discovery (T1482)
- Account discovery (T1087)
- BloodHound AD enumeration: identify attack paths to Domain Admin
- Process discovery, file discovery
- Cloud discovery (T1580): cloud resources accessible from compromised host

### TA0008 — Lateral Movement
- Pass-the-Hash (T1550.002): valid NT hashes for auth
- Pass-the-Ticket (T1550.003): Kerberos TGT/TGS
- Overpass-the-Hash (T1550.002 variant): NT hash → Kerberos TGT
- Remote services: WMIExec, PSExec, SMBExec (impacket variants)
- SSH (T1021.004): using harvested keys

### TA0009 — Collection
- Archive collected data (T1560): zip + encrypt before exfil
- Clipboard data (T1115)
- Email collection (T1114): PST export from Exchange/O365
- Screen capture (T1113): periodic screenshots

### TA0010 — Exfiltration
- HTTPS to C2 (T1041): blend with normal traffic
- DNS exfiltration (T1048.003): encode data in DNS queries (slow but very stealthy)
- Cloud storage (T1567): upload to attacker-controlled S3/OneDrive
- Avoid: large FTP transfers, raw TCP to unusual IPs

### TA0011 — Command & Control
**C2 infrastructure planning:**
- Short-haul beacons: frequent check-in (every 30-60s) for interactive access
- Long-haul beacons: daily check-in for persistence (survives weekends)
- Redirectors: never expose actual C2 to target network
- Domain fronting: use CDN (Cloudflare, Fastly) to hide C2 destination
- C2 profiles: mimic legitimate traffic (JA3, HTTP headers, URL patterns)
- Malleable C2 profiles (Cobalt Strike/Havoc) to mimic specific legit software

## Active Directory Attack Chain

The most common high-impact red team path:

```
External Recon → Phishing/CVE → Initial Access (workstation)
→ Local Privesc → Credential Access (LSASS dump)
→ Lateral Movement (Pass-the-Hash to server)
→ BloodHound analysis → Kerberoasting / DCSync path
→ Domain Compromise → Golden Ticket (persistent access)
→ Data Collection → Staged Exfil via C2
```

## Operational Security (OPSEC)

**Before every action:**
- "Will this generate a log/alert?"
- "Is this technique known to AV/EDR?"
- "Can I achieve the same objective more quietly?"

**Anti-forensics:**
- Clear PowerShell history (ConsoleHost_history.txt)
- Clear Windows Event logs (but this itself triggers alerts)
- Use in-memory execution — avoid writing to disk
- Use legitimate process names for C2 (svchost.exe, lsass.exe level blending)

## Red Team Report Structure

Different from pentest report — focuses on:
1. **Objectives achieved**: did we reach the mission goal?
2. **Detections triggered**: when did the blue team see us? (none = poor detection)
3. **Detection gaps**: what went undetected? (these are the real findings)
4. **Dwell time**: how long before detected or mission completed?
5. **TTPs used**: MITRE ATT&CK heatmap showing coverage
6. **Recommendations**: detection rules, monitoring improvements, not just patches

## Guardrails
- Ransomware simulation only with explicit written approval and isolated environments
- Never deploy actual malware payload — use benign beacons only
- Never exfiltrate real data — demonstrate capability, not actual theft
- Always have kill switch for C2 infrastructure
- Coordinate with blue team for deconfliction after each phase (for lessons learned)
