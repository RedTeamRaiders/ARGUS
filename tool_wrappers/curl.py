"""
curl wrapper — alias for http_request.
Claude sometimes calls this tool by name; delegates to http_request.run().
"""
from tool_wrappers.http_request import run

__all__ = ["run"]
