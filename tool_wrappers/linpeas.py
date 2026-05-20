"""
LinPEAS / WinPEAS wrapper — privilege escalation enumeration.
Runs linpeas.sh or winpeas.exe on remote target via existing shell session.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from shared.logger import audit

TOOL = "linpeas"
TIMEOUT = 120

# Known paths for linpeas
LINPEAS_PATHS = [
    "/opt/PEAS/linPEAS/linpeas.sh",
    "/usr/share/peass/linpeas/linpeas.sh",
    "/opt/peass/linpeas.sh",
    "/tmp/linpeas.sh",
]
WINPEAS_PATHS = [
    "/opt/PEAS/winPEAS/winPEASany.exe",
    "/usr/share/peass/winpeas/winPEASany.exe",
    "/opt/peass/winpeas.exe",
]


async def run(
    target: str,
    os_type: str = "linux",
    session_type: str = "local",  # local | ssh | shell
    ssh_user: str = "",
    ssh_key: str = "",
    timeout: int = TIMEOUT,
) -> dict:
    audit.tool_call(TOOL, "run", {"target": target, "os": os_type, "session": session_type})

    if os_type == "linux":
        script_path = _find_script(LINPEAS_PATHS)
        if not script_path and shutil.which("curl"):
            # Download if not found
            script_path = await _download_linpeas()
    else:
        script_path = _find_script(WINPEAS_PATHS)

    if not script_path:
        audit.error(TOOL, f"{'linpeas' if os_type == 'linux' else 'winpeas'} not found")
        return {"error": "script not found", "paths_checked": LINPEAS_PATHS if os_type == "linux" else WINPEAS_PATHS}

    if session_type == "local":
        return await _run_local(script_path, os_type, timeout)
    elif session_type == "ssh":
        return await _run_via_ssh(script_path, target, ssh_user, ssh_key, timeout)

    return {"error": "unsupported session type"}


async def _run_local(script_path: str, os_type: str, timeout: int) -> dict:
    if os_type == "linux":
        cmd = ["bash", script_path, "-a"]  # -a = all checks
    else:
        cmd = [script_path, "log", "/tmp/winpeas_output.txt"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode(errors="replace")
        return _parse_output(output, os_type)
    except asyncio.TimeoutError:
        audit.error(TOOL, "LinPEAS timed out")
        return {"error": "timeout"}
    except Exception as e:
        audit.error(TOOL, f"LinPEAS failed: {e}")
        return {"error": str(e)}


async def _run_via_ssh(script_path: str, target: str, user: str, key: str, timeout: int) -> dict:
    # Upload and execute via SSH
    import tempfile, os
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
    if key:
        ssh_opts.extend(["-i", key])

    # SCP the script
    scp_cmd = ["scp"] + ssh_opts + [script_path, f"{user}@{target}:/tmp/argus_peas.sh"]
    try:
        proc = await asyncio.create_subprocess_exec(*scp_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await asyncio.wait_for(proc.communicate(), timeout=30)
    except Exception as e:
        return {"error": f"SCP failed: {e}"}

    # Execute via SSH
    ssh_cmd = ["ssh"] + ssh_opts + [f"{user}@{target}", "bash /tmp/argus_peas.sh -a 2>/dev/null"]
    try:
        proc = await asyncio.create_subprocess_exec(*ssh_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return _parse_output(stdout.decode(errors="replace"), "linux")
    except Exception as e:
        return {"error": f"SSH execution failed: {e}"}


async def _download_linpeas() -> str:
    dest = "/tmp/linpeas.sh"
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh",
            "-o", dest,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)
        if Path(dest).exists():
            return dest
    except Exception:
        pass
    return ""


def _parse_output(output: str, os_type: str) -> dict:
    result = {
        "raw":          output[:10000],
        "sudo_rights":  [],
        "suid_binaries":[],
        "writable_paths":[],
        "credentials":  [],
        "cron_jobs":    [],
        "interesting":  [],
    }

    lines = output.splitlines()
    for line in lines:
        line_lower = line.lower().strip()
        if "sudo" in line_lower and ("nopasswd" in line_lower or "ALL" in line):
            result["sudo_rights"].append(line.strip())
        if "/bin/" in line and "SUID" in line or "rwsr" in output and line.strip().startswith("/"):
            result["suid_binaries"].append(line.strip())
        if "password" in line_lower and "=" in line:
            result["credentials"].append(line.strip()[:200])
        if "cron" in line_lower and ("root" in line_lower or "/etc/cron" in line_lower):
            result["cron_jobs"].append(line.strip())

    return result


def _find_script(paths: list[str]) -> str:
    for p in paths:
        if Path(p).exists():
            return p
    return ""
