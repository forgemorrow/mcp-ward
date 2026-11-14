"""Clean, deterministic example MCP server without toxic capabilities."""

from __future__ import annotations


class _DemoServer:
    @staticmethod
    def tool(fn):
        return fn


mcp = _DemoServer()


@mcp.tool
def add_numbers(a: int, b: int) -> int:
    """Return the exact integer sum of two inputs."""
    return a + b


@mcp.tool
def format_markdown_heading(title: str, level: int = 2) -> str:
    """Format a safe Markdown section heading clamped between levels 1 and 6."""
    clamped = max(1, min(6, level))
    return f"{'#' * clamped} {title.strip()}"
