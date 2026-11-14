"""Core domain models for mcp-ward."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Finding severity level with deterministic risk weights and ordering."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Return numeric penalty added to workspace risk score."""
        return _SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Return comparable severity rank (higher means more severe)."""
        return _SEVERITY_RANKS[self]


_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 12,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

_SEVERITY_RANKS: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class CapabilityCategory(str, Enum):
    """Tool security capability classes used in toxic-flow graph analysis."""

    UNTRUSTED_INPUT = "UNTRUSTED_INPUT"
    SENSITIVE_READ = "SENSITIVE_READ"
    EXTERNAL_SINK = "EXTERNAL_SINK"
    DESTRUCTIVE_EXEC = "DESTRUCTIVE_EXEC"


@dataclass
class Finding:
    """Single security issue discovered during static or capability analysis."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    file_path: str
    line: int = 1
    snippet: str = ""
    recommendation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding into a JSON-compatible dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ToolDefinition:
    """Extracted MCP tool or skill entry with inferred capabilities."""

    name: str
    description: str
    source_file: str
    line: int = 1
    parameters: list[str] = field(default_factory=list)
    capabilities: set[CapabilityCategory] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Serialize tool metadata into a JSON-compatible dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "source_file": self.source_file,
            "line": self.line,
            "parameters": list(self.parameters),
            "capabilities": sorted(cap.value for cap in self.capabilities),
        }


@dataclass
class ToxicFlowChain:
    """Multi-tool escalation path across discovered capabilities."""

    chain_id: str
    source_tool: str
    bridge_tool: Optional[str]
    sink_tool: str
    severity: Severity
    attack_narrative: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize toxic flow chain into a JSON-compatible dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


def compute_security_posture(findings: list[Finding]) -> tuple[int, str]:
    """Compute bounded [0, 100] risk score and A-F letter grade."""
    risk_score = min(100, sum(finding.severity.weight for finding in findings))
    if risk_score <= 10:
        grade = "A"
    elif risk_score <= 30:
        grade = "B"
    elif risk_score <= 59:
        grade = "C"
    elif risk_score <= 79:
        grade = "D"
    else:
        grade = "F"
    return risk_score, grade


@dataclass
class ScanReport:
    """Complete static scan and toxic-flow audit report for a workspace."""

    target: str
    files_scanned: int
    tools_discovered: list[ToolDefinition]
    findings: list[Finding]
    toxic_flows: list[ToxicFlowChain]
    risk_score: int
    security_grade: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full report into a JSON-compatible dictionary."""
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "tools_discovered": [tool.to_dict() for tool in self.tools_discovered],
            "findings": [finding.to_dict() for finding in self.findings],
            "toxic_flows": [flow.to_dict() for flow in self.toxic_flows],
            "risk_score": self.risk_score,
            "security_grade": self.security_grade,
        }
