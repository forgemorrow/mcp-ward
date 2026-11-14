"""Multi-target AST and configuration security auditor for MCP servers and skills."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from ..models import CapabilityCategory, Finding, Severity, ToolDefinition
from .flow_graph import classify_tool_capabilities
from .stego_detector import scan_text_for_poisoning

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")),
    ("GitHub personal access token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)

_PATH_VALIDATION_HINTS = {
    "resolve",
    "is_relative_to",
    "commonpath",
    "abspath",
    "realpath",
    "normpath",
}

_SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_output", "check_call"}
_PATH_READ_METHODS = {"read_text", "write_text", "read_bytes", "write_bytes", "open"}
_UNSAFE_ROOT_PATHS = {"/", "\\", "c:\\", "c:/", "/etc", "~", "~/.ssh", "c:\\users"}
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _is_mcp_tool_decorator(decorator: ast.AST) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Name):
        return target.id == "tool"
    if isinstance(target, ast.Attribute):
        if target.attr == "tool":
            return True
    return False


def _call_name(node: ast.Call) -> tuple[str | None, str | None]:
    func = node.func
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute):
        owner = func.value.id if isinstance(func.value, ast.Name) else None
        return owner, func.attr
    return None, None


def _expr_references_names(node: ast.AST, target_names: set[str]) -> bool:
    return any(isinstance(sub, ast.Name) and sub.id in target_names for sub in ast.walk(node))


def _function_has_path_guard(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Attribute) and node.attr in _PATH_VALIDATION_HINTS:
            return True
        if isinstance(node, ast.Name) and node.id in _PATH_VALIDATION_HINTS:
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value == "..":
            return True
    return False


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[Finding] = []
    for item in findings:
        key = (item.rule_id, item.file_path, item.line, item.snippet)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _audit_python(content: str, rel_path: str) -> tuple[list[ToolDefinition], list[Finding]]:
    tools: list[ToolDefinition] = []
    findings: list[Finding] = scan_text_for_poisoning(content, rel_path)

    try:
        tree = ast.parse(content, filename=rel_path)
    except SyntaxError:
        return tools, findings

    # Scan evaluated string constants for escape-encoded smuggling (e.g. \u200b or \U000e0069)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            findings.extend(
                scan_text_for_poisoning(node.value, rel_path, base_line=getattr(node, "lineno", 1))
            )
            for label, pat in _SECRET_PATTERNS:
                if pat.search(node.value):
                    findings.append(
                        Finding(
                            rule_id="MW-AST-004",
                            title=f"Hardcoded Secret Detected ({label})",
                            severity=Severity.HIGH,
                            category="hardcoded-secret",
                            file_path=rel_path,
                            line=getattr(node, "lineno", 1),
                            snippet=f"Hardcoded {label} literal in Python source",
                            recommendation="Load credentials from environment variables or a secret store.",
                        )
                    )

    # Audit functions & tool decorators
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            param_names = {
                arg.arg for arg in node.args.args if arg.arg not in {"self", "cls"}
            }
            is_tool = any(_is_mcp_tool_decorator(dec) for dec in node.decorator_list)
            fn_source = ast.get_source_segment(content, node) or ""
            if is_tool:
                doc = ast.get_docstring(node) or ""
                tool = ToolDefinition(
                    name=node.name,
                    description=doc,
                    source_file=rel_path,
                    line=node.lineno,
                    parameters=[arg.arg for arg in node.args.args if arg.arg not in {"self", "cls"}],
                )
                tool.capabilities = classify_tool_capabilities(tool, fn_source)
                tools.append(tool)

            has_guard = _function_has_path_guard(node)
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                owner, name = _call_name(sub)

                if name == "open" and owner is None and param_names and sub.args:
                    if not has_guard and _expr_references_names(sub.args[0], param_names):
                        findings.append(
                            Finding(
                                rule_id="MW-AST-003",
                                title="Unvalidated File Path Parameter in open()",
                                severity=Severity.HIGH,
                                category="path-traversal",
                                file_path=rel_path,
                                line=sub.lineno,
                                snippet=ast.get_source_segment(content, sub) or "open(...)",
                                recommendation=(
                                    "Resolve target path relative to an allowlisted root and verify "
                                    "with Path.is_relative_to() before opening."
                                ),
                            )
                        )
                elif name in _PATH_READ_METHODS and param_names:
                    target_obj = sub.func.value if isinstance(sub.func, ast.Attribute) else None
                    if target_obj and not has_guard and _expr_references_names(target_obj, param_names):
                        findings.append(
                            Finding(
                                rule_id="MW-AST-003",
                                title=f"Unvalidated Path Access via .{name}()",
                                severity=Severity.HIGH,
                                category="path-traversal",
                                file_path=rel_path,
                                line=sub.lineno,
                                snippet=ast.get_source_segment(content, sub) or f"Path.{name}()",
                                recommendation=(
                                    "Resolve and enforce an allowlisted base directory with "
                                    "Path.is_relative_to()."
                                ),
                            )
                        )

        if isinstance(node, ast.Call):
            owner, name = _call_name(node)
            if owner == "subprocess" and name in _SUBPROCESS_FUNCS:
                shell_true = any(
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true:
                    findings.append(
                        Finding(
                            rule_id="MW-AST-001",
                            title="Command Injection Risk via subprocess(..., shell=True)",
                            severity=Severity.CRITICAL,
                            category="command-injection",
                            file_path=rel_path,
                            line=node.lineno,
                            snippet=ast.get_source_segment(content, node) or "subprocess(..., shell=True)",
                            recommendation="Pass an argument list with shell=False instead of invoking a shell.",
                        )
                    )
            elif owner == "os" and name in {"system", "popen"}:
                findings.append(
                    Finding(
                        rule_id="MW-AST-001",
                        title=f"Shell Execution Risk via os.{name}()",
                        severity=Severity.CRITICAL,
                        category="command-injection",
                        file_path=rel_path,
                        line=node.lineno,
                        snippet=ast.get_source_segment(content, node) or f"os.{name}(...)",
                        recommendation="Replace os.system/os.popen with subprocess.run(..., shell=False).",
                    )
                )
            elif owner is None and name in {"eval", "exec", "__import__"}:
                findings.append(
                    Finding(
                        rule_id="MW-AST-002",
                        title=f"Dynamic Code Execution via {name}()",
                        severity=Severity.CRITICAL,
                        category="code-execution",
                        file_path=rel_path,
                        line=node.lineno,
                        snippet=ast.get_source_segment(content, node) or f"{name}(...)",
                        recommendation="Remove eval/exec/__import__ and dispatch against explicit allowlists.",
                    )
                )

    return tools, _dedupe_findings(findings)


def _walk_json_strings(obj: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, list):
        for item in obj:
            strings.extend(_walk_json_strings(item))
    elif isinstance(obj, dict):
        for val in obj.values():
            strings.extend(_walk_json_strings(val))
    return strings


def _audit_json(content: str, rel_path: str) -> tuple[list[ToolDefinition], list[Finding]]:
    tools: list[ToolDefinition] = []
    findings: list[Finding] = scan_text_for_poisoning(content, rel_path)

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return tools, findings

    for text_val in _walk_json_strings(data):
        findings.extend(scan_text_for_poisoning(text_val, rel_path))

    if isinstance(data, dict):
        servers = data.get("mcpServers")
        if isinstance(servers, dict):
            for server_name, cfg in servers.items():
                if not isinstance(cfg, dict):
                    continue
                cmd = str(cfg.get("command", ""))
                args = [str(a) for a in (cfg.get("args") or []) if isinstance(a, (str, int, float))]
                combined = f"{cmd} {' '.join(args)}".strip()
                desc = str(cfg.get("description", "")) or combined

                tool = ToolDefinition(
                    name=str(server_name),
                    description=desc,
                    source_file=rel_path,
                    line=1,
                    parameters=[],
                )
                tool.capabilities = classify_tool_capabilities(tool, combined)
                tools.append(tool)

                # Check root filesystem exposure or unpinned remote script execution
                for arg in args:
                    normalized = arg.strip().lower().rstrip("/") if arg.strip() not in {"/", "\\"} else arg.strip()
                    if normalized in _UNSAFE_ROOT_PATHS:
                        findings.append(
                            Finding(
                                rule_id="MW-CFG-001",
                                title=f"Broad Filesystem Root Exposure in MCP Server '{server_name}'",
                                severity=Severity.HIGH,
                                category="unsafe-config",
                                file_path=rel_path,
                                line=1,
                                snippet=f"{server_name}: {cmd} {' '.join(args)}",
                                recommendation="Restrict mounted directories to a dedicated project sandbox path.",
                            )
                        )
                        break

                if cmd in {"npx", "uvx"} and "-y" in args and any(
                    a.startswith(("http://", "https://")) or "@" not in a.lstrip("@")
                    for a in args
                    if a != "-y" and not a.startswith("-")
                ):
                    findings.append(
                        Finding(
                            rule_id="MW-CFG-001",
                            title=f"Unpinned Dynamic Package Execution in MCP Server '{server_name}'",
                            severity=Severity.HIGH,
                            category="unsafe-config",
                            file_path=rel_path,
                            line=1,
                            snippet=f"{server_name}: {cmd} {' '.join(args)}",
                            recommendation="Pin explicit package versions (e.g., pkg@1.2.3) instead of auto-installing unpinned targets.",
                        )
                    )

        raw_tools = data.get("tools")
        if isinstance(raw_tools, list):
            for item in raw_tools:
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                schema_props = (
                    item.get("inputSchema", {}).get("properties", {})
                    if isinstance(item.get("inputSchema"), dict)
                    else {}
                )
                tool = ToolDefinition(
                    name=str(item["name"]),
                    description=str(item.get("description", "")),
                    source_file=rel_path,
                    line=1,
                    parameters=list(schema_props.keys()) if isinstance(schema_props, dict) else [],
                )
                tool.capabilities = classify_tool_capabilities(tool, str(item))
                tools.append(tool)

    return tools, _dedupe_findings(findings)


def _audit_markdown(content: str, rel_path: str) -> tuple[list[ToolDefinition], list[Finding]]:
    findings = scan_text_for_poisoning(content, rel_path)
    name = Path(rel_path).stem
    description = ""

    fm_match = _FRONTMATTER_RE.match(content)
    if fm_match:
        for line in fm_match.group(1).splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip().strip('"').strip("'")
                if key == "name" and val:
                    name = val
                elif key == "description" and val:
                    description = val

    if not description:
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("# "):
                description = stripped[2:].strip()
                break

    tool = ToolDefinition(
        name=name,
        description=description,
        source_file=rel_path,
        line=1,
        parameters=[],
    )
    tool.capabilities = classify_tool_capabilities(tool, content)
    return [tool], findings


def audit_file(file_path: Path, rel_path: str) -> tuple[list[ToolDefinition], list[Finding]]:
    """Audit a single Python, JSON, or Markdown/Skill file."""
    suffix = file_path.suffix.lower()
    content = file_path.read_text(encoding="utf-8", errors="replace")

    if suffix == ".py":
        return _audit_python(content, rel_path)
    if suffix == ".json":
        return _audit_json(content, rel_path)
    if suffix in {".md", ".mdx", ".txt"} or file_path.name == ".cursorrules":
        return _audit_markdown(content, rel_path)
    return [], []
