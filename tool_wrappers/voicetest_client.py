"""
voicetest.dev REST API client — automated voice agent testing.
Reference: voicetest.dev (open-source voice agent testing platform)
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

from shared.logger import audit

TOOL = "voicetest"
BASE_URL = "https://api.voicetest.dev"
DEFAULT_TIMEOUT = 120  # voice tests take longer than typical HTTP requests


async def run_test(
    target: str,
    scenario: str,
    attack_type: str = "direct",
    payload: str = "",
    record_response: bool = True,
    transcribe: bool = True,
    api_key: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """
    Execute a single voice attack scenario via the voicetest.dev API.

    target: phone number (+1-555-0123), SIP URI (sip:user@host), or WebSocket URL
    scenario: prompt_injection | jailbreak | ivr_bypass | biometric_bypass | acoustic | social_engineering
    attack_type: direct | indirect | acoustic
    payload: the spoken/injected content
    """
    try:
        import httpx
    except ImportError:
        audit.error(TOOL, "httpx not installed — pip install httpx")
        return {}

    if not api_key:
        audit.warn(TOOL, "No voicetest.dev API key provided — running in simulation mode")
        return _simulate_test(target, scenario, attack_type, payload)

    audit.tool_call(TOOL, "run_test", {
        "target": target,
        "scenario": scenario,
        "attack_type": attack_type,
        "payload_length": len(payload),
    })

    body = {
        "target": target,
        "scenario": scenario,
        "attack_type": attack_type,
        "payload": payload,
        "record_response": record_response,
        "transcribe": transcribe,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{BASE_URL}/api/v1/test/run",
                json=body,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        audit.error(TOOL, f"voicetest.dev timed out after {timeout}s")
        return {}
    except httpx.HTTPStatusError as e:
        audit.error(TOOL, f"voicetest.dev HTTP {e.response.status_code}: {e.response.text[:200]}")
        return {}
    except Exception as e:
        audit.error(TOOL, f"voicetest.dev error: {e}")
        return {}

    return _parse_test_result(data)


async def get_test_result(test_id: str, api_key: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Poll for results of an async voice test by test_id."""
    try:
        import httpx
    except ImportError:
        return {}

    audit.tool_call(TOOL, "get_result", {"test_id": test_id})

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{BASE_URL}/api/v1/test/{test_id}",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            resp.raise_for_status()
            return _parse_test_result(resp.json())
    except Exception as e:
        audit.error(TOOL, f"get_result error: {e}")
        return {}


async def list_scenarios(api_key: str) -> list[dict]:
    """List available test scenarios on voicetest.dev."""
    try:
        import httpx
    except ImportError:
        return []

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{BASE_URL}/api/v1/scenarios",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            resp.raise_for_status()
            return resp.json().get("scenarios", [])
    except Exception as e:
        audit.error(TOOL, f"list_scenarios error: {e}")
        return []


async def run_scenario_batch(
    target: str,
    scenarios: list[dict],
    api_key: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict]:
    """
    Run multiple scenarios sequentially (one at a time — voice calls cannot overlap).

    scenarios: list of dicts with keys: scenario, attack_type, payload
    """
    results = []
    for s in scenarios:
        result = await run_test(
            target=target,
            scenario=s.get("scenario", "prompt_injection"),
            attack_type=s.get("attack_type", "direct"),
            payload=s.get("payload", ""),
            api_key=api_key,
            timeout=timeout,
        )
        if result:
            results.append(result)
        # Pause between calls to avoid rate limiting and appear human
        await asyncio.sleep(3)

    return results


def _parse_test_result(data: dict) -> dict:
    """Normalize voicetest.dev API response into structured result."""
    return {
        "test_id":          data.get("test_id", ""),
        "status":           data.get("status", "unknown"),       # pending | running | complete | failed
        "target":           data.get("target", ""),
        "scenario":         data.get("scenario", ""),
        "attack_type":      data.get("attack_type", ""),
        "payload":          data.get("payload", ""),

        # Audio evidence
        "audio_input_url":  data.get("audio_input_url", ""),     # recording of attack audio
        "audio_output_url": data.get("audio_output_url", ""),    # recording of system response

        # ASR results
        "asr_transcript":   data.get("transcription", {}).get("input", ""),
        "response_transcript": data.get("transcription", {}).get("response", ""),

        # System action
        "action_taken":     data.get("action_taken", ""),
        "action_details":   data.get("action_details", {}),

        # Result assessment
        "succeeded":        data.get("succeeded", False),
        "vulnerability":    data.get("vulnerability", ""),
        "severity":         data.get("severity", ""),
        "notes":            data.get("notes", ""),

        # Metadata
        "duration_s":       data.get("duration_seconds", 0),
        "timestamp":        data.get("timestamp", ""),
        "raw":              json.dumps(data)[:2000],
    }


def _simulate_test(target: str, scenario: str, attack_type: str, payload: str) -> dict:
    """Return a simulation-mode placeholder result when no API key is provided."""
    audit.info(TOOL, f"Simulation mode: {scenario}/{attack_type} against {target}")
    return {
        "test_id":              "simulation",
        "status":               "complete",
        "target":               target,
        "scenario":             scenario,
        "attack_type":          attack_type,
        "payload":              payload,
        "audio_input_url":      "",
        "audio_output_url":     "",
        "asr_transcript":       f"[Simulated ASR transcript for {scenario}]",
        "response_transcript":  "[Simulated system response — no API key provided]",
        "action_taken":         "",
        "action_details":       {},
        "succeeded":            False,
        "vulnerability":        "",
        "severity":             "",
        "notes":                "Simulation mode — provide VOICETEST_API_KEY for live testing",
        "duration_s":           0,
        "timestamp":            "",
        "raw":                  "{}",
    }
