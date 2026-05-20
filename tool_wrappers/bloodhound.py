"""
BloodHound wrapper — Active Directory attack path analysis.
Runs SharpHound for collection and queries BloodHound/Neo4j for attack paths.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from shared.logger import audit

TOOL = "bloodhound"
TIMEOUT = 120


async def run(
    target: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    collection_method: str = "All",
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_pass: str = "neo4j",
    timeout: int = TIMEOUT,
) -> dict:
    audit.tool_call(TOOL, "run", {"target": target, "domain": domain, "collection": collection_method})

    # Try to connect to existing BloodHound/Neo4j instance for queries
    try:
        from neo4j import AsyncGraphDatabase
        result = await _query_bloodhound(neo4j_uri, neo4j_user, neo4j_pass, target, domain)
        if result:
            audit.tool_call(TOOL, "result", {"paths_found": len(result.get("attack_paths", []))})
            return result
    except ImportError:
        audit.error(TOOL, "neo4j driver not installed — pip install neo4j")
    except Exception as e:
        audit.error(TOOL, f"BloodHound query failed: {e}")

    # Fall back to SharpHound collection
    if shutil.which("SharpHound") or shutil.which("SharpHound.exe"):
        return await _run_sharphound(target, domain, username, password, collection_method, timeout)

    # BloodHound CE via bloodhound-python
    if shutil.which("bloodhound-python"):
        return await _run_bloodhound_python(target, domain, username, password, timeout)

    audit.error(TOOL, "No BloodHound collection method available (need SharpHound or bloodhound-python)")
    return {}


async def _query_bloodhound(
    uri: str, user: str, password: str, target: str, domain: str
) -> dict:
    from neo4j import AsyncGraphDatabase

    async with AsyncGraphDatabase.driver(uri, auth=(user, password)) as driver:
        result = {
            "attack_paths": [],
            "domain_admins": [],
            "kerberoastable": [],
            "asreproastable": [],
            "da_shortest_path": [],
        }

        async with driver.session() as session:
            # Shortest path to Domain Admin
            try:
                da_paths = await session.run(
                    "MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@' + $domain})) RETURN p LIMIT 5",
                    domain=domain.upper() if domain else ""
                )
                async for record in da_paths:
                    path = record["p"]
                    nodes = [n.get("name", "") for n in path.nodes]
                    result["da_shortest_path"].append(nodes)
            except Exception:
                pass

            # Kerberoastable accounts
            try:
                kerb = await session.run(
                    "MATCH (u:User {hasspn:true}) RETURN u.name, u.admincount LIMIT 20"
                )
                async for record in kerb:
                    result["kerberoastable"].append({
                        "name": record["u.name"],
                        "is_admin": record["u.admincount"],
                    })
            except Exception:
                pass

            # AS-REP roastable
            try:
                asrep = await session.run(
                    "MATCH (u:User {dontreqpreauth:true}) RETURN u.name LIMIT 20"
                )
                async for record in asrep:
                    result["asreproastable"].append(record["u.name"])
            except Exception:
                pass

        return result


async def _run_bloodhound_python(
    target: str, domain: str, username: str, password: str, timeout: int
) -> dict:
    cmd = [
        "bloodhound-python",
        "-d", domain,
        "-u", username,
        "-p", password,
        "-ns", target,
        "-c", "All",
        "--zip",
    ]
    audit.tool_call(TOOL, "collect_python", {"domain": domain, "target": target})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode() + stderr.decode()
        return {
            "collection_complete": "Finished" in output,
            "raw": output[:2000],
            "note": "Import the generated ZIP into BloodHound CE for path analysis",
        }
    except Exception as e:
        return {"error": str(e)}


async def _run_sharphound(
    target: str, domain: str, username: str, password: str,
    method: str, timeout: int,
) -> dict:
    binary = shutil.which("SharpHound") or shutil.which("SharpHound.exe") or "SharpHound.exe"
    cmd = [binary, "-c", method, "--outputdirectory", "/tmp/bloodhound_output/"]

    if domain:
        cmd.extend(["--domain", domain])
    if username and password:
        cmd.extend(["--ldapusername", username, "--ldappassword", password])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "collection_complete": True,
            "output_dir": "/tmp/bloodhound_output/",
            "raw": stdout.decode()[:2000],
        }
    except Exception as e:
        return {"error": str(e)}
