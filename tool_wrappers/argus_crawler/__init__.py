"""
ARGUS Crawler — Playwright-based web application crawler.

Navigates and interacts like a human tester:
- BFS page discovery with deduplication
- Full input surface detection (standard + rich text + shadow DOM + dynamic)
- Context-aware payload injection
- Multi-signal XSS monitoring (alert, console, DOM, network callbacks)
- Evidence collection per finding (screenshot + HAR + DOM snapshot)
"""
from .crawler import ArgusCrawler
from .form_detector import FormDetector
from .payload_injector import PayloadInjector
from .monitor import ExecutionMonitor
from .auth_handler import AuthHandler
from .rich_text_handler import RichTextHandler
from .evidence_collector import EvidenceCollector

__all__ = [
    "ArgusCrawler",
    "FormDetector",
    "PayloadInjector",
    "ExecutionMonitor",
    "AuthHandler",
    "RichTextHandler",
    "EvidenceCollector",
]
