"""
skill_catalog.py — generic SKILL.md frontmatter catalog.

Discovers skill files under a directory tree, parses their YAML frontmatter,
and answers hard eligibility queries. Knows nothing about OWASP or any
other taxonomy — `owasp_id`/`vuln_class` and any other extra frontmatter
fields are opaque metadata it passes through unexamined. This mirrors
shared/coverage_gate.py's genericness: taxonomy-specific knowledge belongs
in the caller (agents/base_agent.py's skill-loading step), not here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_FRONTMATTER_DELIM = "---"


@dataclass
class SkillFile:
    path: str                              # path relative to the catalog root
    body: str                              # markdown body, frontmatter stripped
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def test_mode(self) -> str:
        return self.meta.get("test_mode", "both")

    @property
    def requires(self) -> list[str]:
        return self.meta.get("requires", []) or []

    @property
    def primitive(self) -> str:
        return self.meta.get("primitive", "")


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split a SKILL.md file into (frontmatter dict, body). No frontmatter -> ({}, full text)."""
    stripped = text.lstrip()
    if not stripped.startswith(_FRONTMATTER_DELIM):
        return {}, text
    parts = stripped.split(_FRONTMATTER_DELIM, 2)
    if len(parts) < 3:
        return {}, text
    _, fm_text, body = parts
    try:
        meta = yaml.safe_load(fm_text) or {}
    except yaml.YAMLError:
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return meta, body.lstrip("\n")


def load_catalog(root: Path) -> list[SkillFile]:
    """Discover every *SKILL.md file under root and parse its frontmatter."""
    skills: list[SkillFile] = []
    if not root.exists():
        return skills
    for p in sorted(root.rglob("*SKILL.md")):
        try:
            text = p.read_text()
        except OSError:
            continue
        meta, body = _parse_frontmatter(text)
        skills.append(SkillFile(path=str(p.relative_to(root)), body=body, meta=meta))
    return skills


def eligible(
    skills: list[SkillFile],
    engagement_modes: set[str],
    available_requirements: set[str],
) -> list[SkillFile]:
    """
    Hard eligibility filter — test_mode gates BEFORE any relevance scoring.
    Call this first in the skill-loading step; narrow the result further
    by stack-tag/relevance signals afterward, never the other way around.

    A skill is eligible when:
      - test_mode is "training_only" -> NEVER eligible for live selection
        (see skills/_training/juice_shop_reference.md)
      - test_mode is "both", or intersects engagement_modes
      - every entry in `requires` is present in available_requirements
        (e.g. "codebase_path" is only satisfied when whitebox mode has
        actual code to review)
    """
    out = []
    for s in skills:
        mode = s.test_mode
        if mode == "training_only":
            continue
        if mode != "both" and mode not in engagement_modes:
            continue
        if not set(s.requires).issubset(available_requirements):
            continue
        out.append(s)
    return out
