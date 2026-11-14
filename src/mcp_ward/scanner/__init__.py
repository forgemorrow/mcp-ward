"""Static security scanning orchestrator for MCP Servers and Agent Skills."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding, ScanReport, ToolDefinition, compute_security_posture
from .ast_auditor import audit_file
from .flow_graph import analyze_toxic_flows

_IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
}

_SUPPORTED_SUFFIXES = {".py", ".json", ".md", ".mdx", ".txt"}


def _iter_scannable_files(target: Path) -> list[tuple[Path, str]]:
    if target.is_file():
        return [(target, target.name)]

    files: list[tuple[Path, str]] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _IGNORED_DIRS for part in path.relative_to(target).parts):
            continue
        if path.suffix.lower() in _SUPPORTED_SUFFIXES or path.name == ".cursorrules":
            files.append((path, path.relative_to(target).as_posix()))
    return files


def scan_path(target: Path) -> ScanReport:
    """Scan a workspace directory or single file and build a structured ScanReport."""
    resolved = target.expanduser()
    if not resolved.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")

    entries = _iter_scannable_files(resolved)
    tools: list[ToolDefinition] = []
    findings: list[Finding] = []

    for abs_path, rel_path in entries:
        file_tools, file_findings = audit_file(abs_path, rel_path)
        tools.extend(file_tools)
        findings.extend(file_findings)

    flow_target = resolved.name or "."
    toxic_flows, flow_findings = analyze_toxic_flows(tools, flow_target)
    findings.extend(flow_findings)

    findings.sort(key=lambda f: (-f.severity.rank, f.file_path, f.line, f.rule_id))
    risk_score, security_grade = compute_security_posture(findings)

    return ScanReport(
        target=target.as_posix(),
        files_scanned=len(entries),
        tools_discovered=tools,
        findings=findings,
        toxic_flows=toxic_flows,
        risk_score=risk_score,
        security_grade=security_grade,
    )


__all__ = ["scan_path"]
