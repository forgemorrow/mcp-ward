"""Capability classification and toxic multi-tool escalation path analysis."""

from __future__ import annotations

import re

from ..models import CapabilityCategory, Finding, Severity, ToolDefinition, ToxicFlowChain

_UNTRUSTED_RE = re.compile(
    r"(\bfetch_url\b|\bfetch_web\b|\bread_webpage\b|\bread_issue\b|\bget_issue\b|"
    r"\bread_email\b|\bfetch_pr\b|\bscrape\b|\brequests\.get\b|\burllib\.request\b|"
    r"\buntrusted\b|\bexternal\s+web\b|\bgithub\s+issue\b|\bpull_request\b|\bfetch_remote\b)",
    re.IGNORECASE,
)

_SENSITIVE_READ_RE = re.compile(
    r"(\bread_secret\b|\bread_env\b|\bget_credentials\b|\b\.env\b|\b\.ssh\b|\bid_rsa\b|"
    r"\bapi[_\s]?key\b|\bcredentials\b|\bpassword\b|\bprivate[_\s]?key\b|"
    r"\bread_file\b|\bcat_file\b|\bworkspace_read\b|\bsensitive\s+file\b)",
    re.IGNORECASE,
)

_EXTERNAL_SINK_RE = re.compile(
    r"(\bsend_http\b|\bhttp_post\b|\bpost_data\b|\bwebhook\b|\bexfiltrat|"
    r"\bsend_email\b|\bupload_report\b|\brequests\.post\b|\boutbound\s+http\b|\btelemetry\s+post\b)",
    re.IGNORECASE,
)

_DESTRUCTIVE_EXEC_RE = re.compile(
    r"(\brun_shell\b|\bexec_command\b|\bshell_exec\b|\bsubprocess\.|"
    r"\bos\.system\b|\bos\.popen\b|\beval\(|\bexec\(|\bshell=True\b|\brun_command\b)",
    re.IGNORECASE,
)


def classify_tool_capabilities(tool: ToolDefinition, source_text: str = "") -> set[CapabilityCategory]:
    """Classify a tool or skill into high-level security capability categories."""
    combined = "\n".join([tool.name, tool.description, " ".join(tool.parameters), source_text])
    caps: set[CapabilityCategory] = set()

    if _UNTRUSTED_RE.search(combined):
        caps.add(CapabilityCategory.UNTRUSTED_INPUT)
    if _SENSITIVE_READ_RE.search(combined):
        caps.add(CapabilityCategory.SENSITIVE_READ)
    if _EXTERNAL_SINK_RE.search(combined):
        caps.add(CapabilityCategory.EXTERNAL_SINK)
    if _DESTRUCTIVE_EXEC_RE.search(combined):
        caps.add(CapabilityCategory.DESTRUCTIVE_EXEC)
    return caps


def _find_tool_for(
    tools: list[ToolDefinition],
    cap: CapabilityCategory,
    prefer_distinct_from: set[str] | None = None,
) -> ToolDefinition | None:
    candidates = [t for t in tools if cap in t.capabilities]
    if not candidates:
        return None
    if prefer_distinct_from:
        distinct = [t for t in candidates if t.name not in prefer_distinct_from]
        if distinct:
            return distinct[0]
    return candidates[0]


def analyze_toxic_flows(
    tools: list[ToolDefinition],
    rel_target: str,
) -> tuple[list[ToxicFlowChain], list[Finding]]:
    """Detect Lethal Trifecta and Untrusted-to-Exec escalation chains across tools."""
    chains: list[ToxicFlowChain] = []
    findings: list[Finding] = []
    if not tools:
        return chains, findings

    ordered_tools = sorted(tools, key=lambda t: (t.source_file, t.line, t.name))
    source_tool = _find_tool_for(ordered_tools, CapabilityCategory.UNTRUSTED_INPUT)
    read_tool = _find_tool_for(
        ordered_tools,
        CapabilityCategory.SENSITIVE_READ,
        prefer_distinct_from={source_tool.name} if source_tool else None,
    )
    sink_tool = _find_tool_for(
        ordered_tools,
        CapabilityCategory.EXTERNAL_SINK,
        prefer_distinct_from={t.name for t in (source_tool, read_tool) if t is not None},
    )
    exec_tool = _find_tool_for(
        ordered_tools,
        CapabilityCategory.DESTRUCTIVE_EXEC,
        prefer_distinct_from={source_tool.name} if source_tool else None,
    )

    if source_tool and read_tool and sink_tool:
        narrative = (
            f"Untrusted content ingested via '{source_tool.name}' can coerce the agent into reading "
            f"local secrets via '{read_tool.name}' and exfiltrating them through '{sink_tool.name}'."
        )
        chains.append(
            ToxicFlowChain(
                chain_id="MW-FLOW-001",
                source_tool=source_tool.name,
                bridge_tool=read_tool.name,
                sink_tool=sink_tool.name,
                severity=Severity.CRITICAL,
                attack_narrative=narrative,
            )
        )
        findings.append(
            Finding(
                rule_id="MW-FLOW-001",
                title="Lethal Trifecta Capability Chain (Untrusted Input + Sensitive Read + External Sink)",
                severity=Severity.CRITICAL,
                category="toxic-flow",
                file_path=rel_target,
                line=sink_tool.line,
                snippet=f"{source_tool.name} -> {read_tool.name} -> {sink_tool.name}",
                recommendation=(
                    "Enable runtime taint tracking with `mcp-ward guard` or split sensitive-read "
                    "and outbound-sink tools across isolated approval scopes."
                ),
                metadata={
                    "source_tool": source_tool.name,
                    "bridge_tool": read_tool.name,
                    "sink_tool": sink_tool.name,
                },
            )
        )

    if source_tool and exec_tool:
        narrative = (
            f"Untrusted input from '{source_tool.name}' can trigger prompt-injected command "
            f"or code execution via '{exec_tool.name}'."
        )
        chains.append(
            ToxicFlowChain(
                chain_id="MW-FLOW-002",
                source_tool=source_tool.name,
                bridge_tool=None,
                sink_tool=exec_tool.name,
                severity=Severity.HIGH,
                attack_narrative=narrative,
            )
        )
        findings.append(
            Finding(
                rule_id="MW-FLOW-002",
                title="Untrusted-to-Exec Capability Chain",
                severity=Severity.HIGH,
                category="toxic-flow",
                file_path=rel_target,
                line=exec_tool.line,
                snippet=f"{source_tool.name} -> {exec_tool.name}",
                recommendation=(
                    "Require explicit human confirmation or runtime argument policy checks "
                    "before allowing execution tools after reading untrusted content."
                ),
                metadata={
                    "source_tool": source_tool.name,
                    "sink_tool": exec_tool.name,
                },
            )
        )

    return chains, findings
