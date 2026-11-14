"""Stateful runtime guardrail policy and tool-response sanitizer."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

from ..models import CapabilityCategory, ToolDefinition
from ..scanner.flow_graph import classify_tool_capabilities
from ..scanner.stego_detector import BIDI_CHARS, ZERO_WIDTH_CHARS

_COMMENT_STRIP_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_IMPORTANT_STRIP_RE = re.compile(r"<\s*important\s*>.*?<\s*/\s*important\s*>", re.DOTALL | re.IGNORECASE)
_PATH_TRAVERSAL_RE = re.compile(r"(?:^|[\\/])\.\.(?:$|[\\/])")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_SHELL_META_RE = re.compile(r"(;|&&|\|\||`|\$\()")
_SECRET_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----"),
)
_CMD_ARG_KEYS = {"cmd", "command", "shell", "script", "bash", "powershell", "exec"}


@dataclass
class PolicyConfig:
    """Configurable runtime policy rules for MCP tool inspection."""

    block_paths: tuple[str, ...] = (
        ".env",
        ".ssh",
        "id_rsa",
        "id_ed25519",
        "/etc/shadow",
        "/etc/passwd",
        ".aws/credentials",
        ".git-credentials",
        ".npmrc",
        ".netrc",
    )
    blocked_domains: tuple[str, ...] = (
        "webhook.site",
        "oastify.com",
        "requestbin.com",
        "ngrok-free.app",
        "pipedream.net",
        "burpcollaborator.net",
    )
    allowed_domains: tuple[str, ...] = ()
    block_shell_metachars: bool = True
    block_secrets: bool = True
    enforce_taint_flow: bool = True
    strip_poisoning_from_tools_list: bool = True


@dataclass
class GuardDecision:
    """Result returned by GuardrailEngine for a tool call inspection."""

    allowed: bool
    rule_id: Optional[str]
    reason: str
    sanitized_data: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }


def _strip_hidden_instructions(text: str) -> str:
    cleaned = _COMMENT_STRIP_RE.sub("", text)
    cleaned = _IMPORTANT_STRIP_RE.sub("", cleaned)
    cleaned = "".join(
        ch
        for ch in cleaned
        if ch not in ZERO_WIDTH_CHARS
        and ch not in BIDI_CHARS
        and not (0xE0000 <= ord(ch) <= 0xE007F)
    )
    return re.sub(r"\n{3,}", "\n\n", cleaned).strip()


def _flatten_strings(obj: Any) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(obj, str):
        items.append(("", obj))
    elif isinstance(obj, list):
        for val in obj:
            items.extend(_flatten_strings(val))
    elif isinstance(obj, dict):
        for key, val in obj.items():
            key_str = str(key).lower()
            if isinstance(val, str):
                items.append((key_str, val))
            else:
                for sub_key, sub_val in _flatten_strings(val):
                    items.append((sub_key or key_str, sub_val))
    return items


class GuardrailEngine:
    """Stateful MCP policy engine enforcing sanitization, argument checks, and taint flow."""

    def __init__(self, policy: Optional[PolicyConfig] = None):
        self.policy = policy or PolicyConfig()
        self.tainted_untrusted: bool = False
        self.tainted_sensitive: bool = False
        self.history: list[str] = []
        self._tool_capabilities: dict[str, set[CapabilityCategory]] = {}

    def reset_session(self) -> None:
        """Clear session taint state and call history."""
        self.tainted_untrusted = False
        self.tainted_sensitive = False
        self.history.clear()

    def register_tools(self, tools: list[dict[str, Any]]) -> None:
        """Index discovered MCP tool schemas and inferred capabilities."""
        for tool in tools:
            name = str(tool.get("name", ""))
            if not name:
                continue
            desc = str(tool.get("description", ""))
            schema = tool.get("inputSchema")
            params = list(schema.get("properties", {}).keys()) if isinstance(schema, dict) else []
            td = ToolDefinition(name=name, description=desc, source_file="runtime", parameters=params)
            self._tool_capabilities[name] = classify_tool_capabilities(td)

    def sanitize_tools_list(
        self, tools: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Strip hidden poisoning from tool descriptions and register capabilities."""
        self.register_tools(tools)
        sanitized: list[dict[str, Any]] = []
        modified: list[str] = []

        for tool in tools:
            cloned = copy.deepcopy(tool)
            desc = cloned.get("description")
            if self.policy.strip_poisoning_from_tools_list and isinstance(desc, str):
                clean_desc = _strip_hidden_instructions(desc)
                if clean_desc != desc:
                    cloned["description"] = clean_desc
                    if cloned.get("name"):
                        modified.append(str(cloned["name"]))
            sanitized.append(cloned)
        return sanitized, modified

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        capabilities: Optional[set[CapabilityCategory]] = None,
    ) -> GuardDecision:
        """Evaluate an outbound MCP tools/call invocation against runtime policy."""
        if capabilities is not None:
            caps = set(capabilities)
        elif tool_name in self._tool_capabilities:
            caps = set(self._tool_capabilities[tool_name])
        else:
            td = ToolDefinition(
                name=tool_name,
                description="",
                source_file="runtime",
                parameters=list(arguments.keys()),
            )
            caps = classify_tool_capabilities(td, str(arguments))

        flat_args = _flatten_strings(arguments)

        # 1. Sensitive path & directory traversal protection
        for _, value in flat_args:
            normalized = value.replace("\\", "/").lower()
            if _PATH_TRAVERSAL_RE.search(value):
                return GuardDecision(
                    allowed=False,
                    rule_id="MW-GUARD-PATH",
                    reason=f"Blocked path traversal attempt in '{tool_name}': {value}",
                )
            for sensitive in self.policy.block_paths:
                token = sensitive.lower()
                if token in normalized:
                    return GuardDecision(
                        allowed=False,
                        rule_id="MW-GUARD-PATH",
                        reason=f"Blocked access to sensitive path pattern '{sensitive}' in '{tool_name}'.",
                    )

        # 2. Shell metacharacter / command chaining defense
        if self.policy.block_shell_metachars:
            is_exec_tool = CapabilityCategory.DESTRUCTIVE_EXEC in caps
            for key, value in flat_args:
                if (is_exec_tool or key in _CMD_ARG_KEYS) and _SHELL_META_RE.search(value):
                    return GuardDecision(
                        allowed=False,
                        rule_id="MW-GUARD-CMD",
                        reason=f"Blocked shell chaining / metacharacters in '{tool_name}' argument '{key}'.",
                    )

        # 3. Secret / credential egress prevention
        if self.policy.block_secrets:
            for _, value in flat_args:
                for pat in _SECRET_RES:
                    if pat.search(value):
                        return GuardDecision(
                            allowed=False,
                            rule_id="MW-GUARD-SECRET",
                            reason=f"Blocked secret/credential material in outbound arguments of '{tool_name}'.",
                        )

        # 4. Outbound domain & exfiltration sink checks
        for _, value in flat_args:
            for match in _URL_RE.finditer(value):
                host = (urlparse(match.group(0)).hostname or "").lower()
                if not host:
                    continue
                if any(host == d or host.endswith(f".{d}") for d in self.policy.blocked_domains):
                    return GuardDecision(
                        allowed=False,
                        rule_id="MW-GUARD-NET",
                        reason=f"Blocked exfiltration domain '{host}' in '{tool_name}'.",
                    )
                if self.policy.allowed_domains and not any(
                    host == d or host.endswith(f".{d}") for d in self.policy.allowed_domains
                ):
                    return GuardDecision(
                        allowed=False,
                        rule_id="MW-GUARD-NET",
                        reason=f"Domain '{host}' is not in PolicyConfig.allowed_domains.",
                    )

        # 5. Stateful Lethal Trifecta / taint-flow enforcement
        if (
            self.policy.enforce_taint_flow
            and CapabilityCategory.EXTERNAL_SINK in caps
            and (self.tainted_sensitive or self.tainted_untrusted)
        ):
            taint_sources = []
            if self.tainted_untrusted:
                taint_sources.append("untrusted input")
            if self.tainted_sensitive:
                taint_sources.append("sensitive read")
            return GuardDecision(
                allowed=False,
                rule_id="MW-GUARD-TAINT",
                reason=(
                    f"Blocked external sink '{tool_name}' because session is tainted by "
                    + " + ".join(taint_sources)
                    + "."
                ),
            )

        # Allowed: update session taint state
        if CapabilityCategory.UNTRUSTED_INPUT in caps:
            self.tainted_untrusted = True
        if CapabilityCategory.SENSITIVE_READ in caps:
            self.tainted_sensitive = True
        self.history.append(tool_name)

        return GuardDecision(
            allowed=True,
            rule_id=None,
            reason=f"Allowed tool call '{tool_name}'.",
        )
