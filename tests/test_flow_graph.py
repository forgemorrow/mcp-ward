"""Tests for capability classification and toxic escalation chains."""

from __future__ import annotations

from mcp_ward.models import CapabilityCategory, ToolDefinition
from mcp_ward.scanner.flow_graph import analyze_toxic_flows, classify_tool_capabilities


def test_capability_classification_and_lethal_trifecta():
    t_input = ToolDefinition(
        name="fetch_github_issue",
        description="Fetch untrusted external GitHub issue body",
        source_file="server.py",
        line=10,
    )
    t_read = ToolDefinition(
        name="read_file",
        description="Read .env or workspace secrets",
        source_file="server.py",
        line=20,
    )
    t_sink = ToolDefinition(
        name="send_http",
        description="Send outbound HTTP webhook payload",
        source_file="server.py",
        line=30,
    )
    t_exec = ToolDefinition(
        name="run_shell",
        description="Execute local shell command via subprocess",
        source_file="server.py",
        line=40,
    )
    t_benign = ToolDefinition(
        name="add_numbers",
        description="Add two integers cleanly",
        source_file="server.py",
        line=50,
    )

    for tool in (t_input, t_read, t_sink, t_exec, t_benign):
        tool.capabilities = classify_tool_capabilities(tool)

    assert CapabilityCategory.UNTRUSTED_INPUT in t_input.capabilities
    assert CapabilityCategory.SENSITIVE_READ in t_read.capabilities
    assert CapabilityCategory.EXTERNAL_SINK in t_sink.capabilities
    assert CapabilityCategory.DESTRUCTIVE_EXEC in t_exec.capabilities
    assert t_benign.capabilities == set()

    chains, findings = analyze_toxic_flows([t_input, t_read, t_sink, t_exec], "workspace")
    assert {c.chain_id for c in chains} == {"MW-FLOW-001", "MW-FLOW-002"}
    assert {f.rule_id for f in findings} == {"MW-FLOW-001", "MW-FLOW-002"}

    safe_chains, safe_findings = analyze_toxic_flows([t_read, t_benign], "workspace")
    assert safe_chains == []
    assert safe_findings == []
