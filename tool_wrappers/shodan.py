"""
Shodan wrapper — external intelligence: open ports, services, CVEs, banners.
"""
from __future__ import annotations

from shared.logger import audit

TOOL = "shodan"


async def run(target: str, query: str = "") -> dict:
    try:
        import shodan as shodan_lib
        from config import SHODAN_API_KEY
        if not SHODAN_API_KEY:
            audit.error(TOOL, "SHODAN_API_KEY not set in environment")
            return {}
        api = shodan_lib.Shodan(SHODAN_API_KEY)
    except ImportError:
        audit.error(TOOL, "shodan library not installed — pip install shodan")
        return {}

    audit.tool_call(TOOL, "lookup", {"target": target})
    try:
        if query:
            results = api.search(query)
            parsed = _parse_search(results)
        else:
            host = api.host(target)
            parsed = _parse_host(host)
        audit.tool_call(TOOL, "result", {"data_points": len(parsed.get("ports", []))})
        return parsed
    except Exception as e:
        audit.error(TOOL, f"Shodan lookup failed: {e}")
        return {}


def _parse_host(host: dict) -> dict:
    return {
        "ip":           host.get("ip_str", ""),
        "hostnames":    host.get("hostnames", []),
        "country":      host.get("country_name", ""),
        "org":          host.get("org", ""),
        "os":           host.get("os", ""),
        "ports":        host.get("ports", []),
        "vulns":        list(host.get("vulns", {}).keys()),
        "services": [
            {
                "port":      svc.get("port"),
                "transport": svc.get("transport"),
                "product":   svc.get("product", ""),
                "version":   svc.get("version", ""),
                "banner":    svc.get("data", "")[:500],
                "cpe":       svc.get("cpe", []),
            }
            for svc in host.get("data", [])
        ],
        "last_updated": host.get("last_update", ""),
    }


def _parse_search(results: dict) -> dict:
    return {
        "total":   results.get("total", 0),
        "matches": [
            {
                "ip":      m.get("ip_str", ""),
                "port":    m.get("port"),
                "banner":  m.get("data", "")[:300],
                "product": m.get("product", ""),
                "version": m.get("version", ""),
                "hostnames": m.get("hostnames", []),
            }
            for m in results.get("matches", [])[:20]
        ],
    }
