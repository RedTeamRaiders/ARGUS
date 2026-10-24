---
owasp_id: A06:2021
vuln_class: vulnerable_components
test_mode: both
requires: []
primitive: known_cve_exploitable
evidence_schema:
  required_proof: [version_fingerprint, cve_exploit_confirmation]
  min_tool_confirmations: 2
  oob_required: false
---

# Skill: Vulnerable and Outdated Components

Single file — blackbox and whitebox methodology converge here. Both modes
reduce to the same core loop: identify exact component versions, match
against known CVEs, confirm exploitability. Whitebox only changes *how*
versions are identified (lockfiles vs external fingerprinting), not what
happens after.

## 1. Recon — Attack Surface Mapping
- **Blackbox**: HTTP response headers (`Server`, `X-Powered-By`), JS
  bundle comments/source maps, error pages revealing framework/library
  versions, `nuclei`'s tech-detection templates, `httpx` tech-stack output
  already collected during active recon.
- **Whitebox** (when `codebase_path` is set): read `package.json`/
  `package-lock.json`, `requirements.txt`/`poetry.lock`,
  `pom.xml`/`build.gradle`, `Gemfile.lock` directly — exact pinned versions,
  not inferred from external fingerprinting.

## 2. Detection Methodology
1. Build a complete component inventory: name + exact version for every
   server-side dependency, client-side JS library, and the underlying
   runtime/framework itself.
2. Run `shared.cve_intel.cves_for_stack(tech_stack)` (already wired into
   `bug_bounty.py`'s active recon pass) to match the inventory against
   CIRCL/NVD — this returns CVSS score and `has_exploit` per match.
3. For pentest's black box flow, `searchsploit` (already wired into
   `pentest.py`'s `_vuln_research`) independently cross-checks ExploitDB
   for public PoC availability — use both sources, they satisfy
   `min_tool_confirmations: 2` together.

## 3. Exploitation Path — Tool Invocation
```python
from shared.cve_intel import cves_for_stack, summarize
records = await cves_for_stack(context.tech_stack, limit_per=5)
```
```python
import tool_wrappers.searchsploit as searchsploit
results = await searchsploit.run(f"{service} {version}")
```
- Prioritize `has_exploit=True` CVEs with public PoC availability over
  theoretical CVSS-high matches with no known exploit.
- Only execute an actual exploit (via Metasploit or a manual PoC) after
  confirming the exact version matches the CVE's affected range — a
  version string that merely looks close is not sufficient confirmation.

## 4. Evidence Capture
`evidence_schema` requires `version_fingerprint` (the exact version string
and where it was obtained — header, lockfile, or banner) AND
`cve_exploit_confirmation` (either a successful exploit execution with
output, or — if non-destructive exploitation isn't safe/available — the
CVE ID with CVSS/exploit-availability data from both `cve_intel` and
`searchsploit` as the two tool confirmations).

## 5. False-Positive Filtering
- A matched CVE whose affected version range doesn't actually include the
  fingerprinted version (off-by-one in range parsing, or a backported
  patch that changes behavior without bumping the version string) — verify
  against the vendor's actual advisory, not just a CVE database's
  range field.
- A client-side library with a known CVE that's never actually invoked in
  an exploitable code path (dead dependency, tree-shaken out of the
  production bundle) — whitebox can confirm via import/usage grep before
  flagging; blackbox should note lower confidence without that confirmation.

## 6. CVSS Vector Construction
Use the CVE's own published CVSS vector as the baseline — don't
re-derive from scratch. Adjust downward only if the specific deployment
context demonstrably mitigates part of the vector (e.g. the vulnerable
function is unreachable without an auth level the CVE assumes is
unauthenticated).

## 7. Remediation (by stack)
- Node: `npm audit fix` / bump to the patched version in `package.json`;
  for transitive deps, use `npm overrides`/`pnpm.overrides` if the direct
  dependency hasn't updated yet.
- Python: bump the pinned version in `requirements.txt`/`pyproject.toml`;
  run `pip-audit` in CI going forward.
- Java: bump the dependency version in `pom.xml`/`build.gradle`; `mvn
  versions:display-dependency-updates` to find available patches.
- General: add a dependency-scanning step (`npm audit`, `pip-audit`,
  `trufflehog` for secrets, `semgrep`/`bandit` already in `tool_wrappers/`)
  to CI so new vulnerable pins are caught before merge, not just at
  pentest time.
