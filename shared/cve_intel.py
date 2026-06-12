"""
CVE Intelligence — fetch CVEs by technology stack.

Hits the public NVD API and CIRCL.LU CVE Search. No API key required for either,
but NVD rate-limits to ~5 req / 30s unauthenticated — keep volume low.

Output feeds the agent's mental model so the think-step can prioritize exploit
templates that match the actual installed versions detected in active recon.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional

import httpx

from shared.logger import audit

NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API = "https://cve.circl.lu/api/search"

CACHE: dict[str, list[dict]] = {}


@dataclass
class CveRecord:
    cve_id:      str
    description: str
    cvss:        float = 0.0
    severity:    str   = ""
    references:  list[str] = field(default_factory=list)
    products:    list[str] = field(default_factory=list)
    has_exploit: bool  = False


async def cves_for_tech(
    vendor: str,
    product: str,
    version: str = "",
    limit: int = 10,
) -> list[CveRecord]:
    """Look up CVEs for vendor/product/version. Tries CIRCL first (no rate limit), then NVD."""
    key = f"{vendor}:{product}:{version}".lower()
    if key in CACHE:
        return CACHE[key]

    records = await _query_circl(vendor, product, version, limit)
    if not records:
        records = await _query_nvd(vendor, product, version, limit)

    CACHE[key] = records
    return records


async def cves_for_stack(tech_stack: list[str], limit_per: int = 5) -> dict[str, list[CveRecord]]:
    """
    Given a list of tech-stack strings (e.g. ["WordPress/6.2", "PHP/7.4"]),
    fan out and return {tech: [CveRecord]}.
    """
    tasks = []
    keys  = []
    for tech in tech_stack:
        vendor, product, version = _split_tech(tech)
        if not product:
            continue
        keys.append(tech)
        tasks.append(cves_for_tech(vendor, product, version, limit_per))

    if not tasks:
        return {}

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {
        k: (r if isinstance(r, list) else [])
        for k, r in zip(keys, results)
    }


def _split_tech(tech: str) -> tuple[str, str, str]:
    """
    Parse strings like:
      "WordPress/6.2"        -> ("", "wordpress", "6.2")
      "Apache httpd 2.4.49"  -> ("apache", "httpd", "2.4.49")
      "nginx"                -> ("", "nginx", "")
    """
    raw = tech.strip().lower()
    if "/" in raw:
        product, _, version = raw.partition("/")
        return ("", product.strip(), version.strip())
    parts = raw.split()
    if len(parts) >= 3 and any(c.isdigit() for c in parts[-1]):
        return (parts[0], parts[1], parts[-1])
    if len(parts) == 2 and any(c.isdigit() for c in parts[1]):
        return ("", parts[0], parts[1])
    return ("", raw, "")


async def _query_circl(vendor: str, product: str, version: str, limit: int) -> list[CveRecord]:
    url = f"{CIRCL_API}/{vendor or 'any'}/{product}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception as e:
        audit.error("cve_intel", f"CIRCL query failed: {e}")
        return []

    records: list[CveRecord] = []
    # CIRCL returns either a list or {data: [...]}
    items = data if isinstance(data, list) else data.get("data", []) or data.get("results", [])
    for item in items[:limit * 3]:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("id") or item.get("cveMetadata", {}).get("cveId") or ""
        if not cve_id:
            continue
        desc = ""
        d = item.get("summary") or item.get("descriptions") or item.get("cna", {}).get("descriptions", [])
        if isinstance(d, list) and d:
            desc = d[0].get("value", "") if isinstance(d[0], dict) else str(d[0])
        elif isinstance(d, str):
            desc = d
        cvss = float(item.get("cvss") or 0.0)
        sev = item.get("cvss3", {}).get("baseSeverity") if isinstance(item.get("cvss3"), dict) else _sev_from_cvss(cvss)
        if version and version not in str(item):
            continue
        records.append(CveRecord(
            cve_id=cve_id,
            description=desc[:500],
            cvss=cvss,
            severity=sev or _sev_from_cvss(cvss),
            references=item.get("references", [])[:5] if isinstance(item.get("references"), list) else [],
            products=[product],
            has_exploit=bool(item.get("exploit-db") or item.get("exploitability")),
        ))
        if len(records) >= limit:
            break
    return records


async def _query_nvd(vendor: str, product: str, version: str, limit: int) -> list[CveRecord]:
    cpe_parts = ["cpe:2.3:a", vendor or "*", product]
    if version:
        cpe_parts.append(version)
    cpe = ":".join(cpe_parts)
    params = {
        "cpeName":        cpe,
        "resultsPerPage": min(limit, 20),
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(NVD_API, params=params)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception as e:
        audit.error("cve_intel", f"NVD query failed: {e}")
        return []

    records: list[CveRecord] = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = cve.get("metrics", {})
        cvss = 0.0
        sev = ""
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if k in metrics and metrics[k]:
                m = metrics[k][0].get("cvssData", {})
                cvss = float(m.get("baseScore") or 0.0)
                sev  = m.get("baseSeverity", "") or _sev_from_cvss(cvss)
                break
        refs = [r.get("url", "") for r in cve.get("references", [])][:5]
        records.append(CveRecord(
            cve_id=cve_id,
            description=desc[:500],
            cvss=cvss,
            severity=sev,
            references=refs,
            products=[product],
            has_exploit=any("exploit" in (r or "").lower() for r in refs),
        ))
    return records


def _sev_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return ""


def summarize(records: dict[str, list[CveRecord]]) -> str:
    """Render a compact Markdown summary for inclusion in an agent prompt."""
    if not records:
        return ""
    lines = ["## CVE Intelligence (matched to detected tech)"]
    for tech, cves in records.items():
        if not cves:
            continue
        lines.append(f"\n### {tech}")
        for c in cves[:5]:
            badge = "🔥" if c.has_exploit else ""
            lines.append(f"- **{c.cve_id}** (CVSS {c.cvss} / {c.severity}) {badge} — {c.description[:140]}")
    return "\n".join(lines) if len(lines) > 1 else ""
