"""JSON-RPC 2.0 stdio security guardrail proxy for MCP servers."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .policy import GuardrailEngine, PolicyConfig


class StdioGuardrailProxy:
    """Intercepts JSON-RPC 2.0 messages between an MCP client and server."""

    def __init__(
        self,
        engine: Optional[GuardrailEngine] = None,
        audit_log: Optional[Path] = None,
    ):
        self.engine = engine or GuardrailEngine(PolicyConfig())
        self.audit_log = audit_log
        self._pending_methods: dict[Any, str] = {}

    def _write_audit(self, event: dict[str, Any]) -> None:
        if self.audit_log is None:
            return
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
        with self.audit_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def handle_client_message(self, raw_line: str) -> tuple[Optional[str], Optional[str]]:
        """Inspect client->server JSON-RPC line. Return (forward_line, immediate_reply)."""
        stripped = raw_line.strip()
        if not stripped:
            return None, None

        try:
            msg = json.loads(stripped)
        except json.JSONDecodeError:
            return raw_line, None

        if not isinstance(msg, dict):
            return raw_line, None

        req_id = msg.get("id")
        method = msg.get("method")
        if req_id is not None and isinstance(method, str):
            self._pending_methods[req_id] = method

        if method == "tools/call":
            params = msg.get("params") or {}
            tool_name = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                arguments = {"value": arguments}
            decision = self.engine.inspect_tool_call(tool_name, arguments)
            if not decision.allowed:
                self._write_audit(
                    {
                        "event": "tool_call_blocked",
                        "tool": tool_name,
                        "rule_id": decision.rule_id,
                        "reason": decision.reason,
                    }
                )
                error_payload = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32001,
                        "message": f"Blocked by mcp-ward [{decision.rule_id}]: {decision.reason}",
                        "data": decision.to_dict(),
                    },
                }
                return None, json.dumps(error_payload, ensure_ascii=False)

            self._write_audit({"event": "tool_call_allowed", "tool": tool_name})

        return stripped, None

    def handle_server_message(self, raw_line: str) -> str:
        """Inspect server->client JSON-RPC line and sanitize tools/list responses."""
        stripped = raw_line.strip()
        if not stripped:
            return ""

        try:
            msg = json.loads(stripped)
        except json.JSONDecodeError:
            return raw_line

        if not isinstance(msg, dict):
            return stripped

        req_id = msg.get("id")
        method = self._pending_methods.pop(req_id, None) if req_id is not None else None
        result = msg.get("result")

        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            if method in (None, "tools/list"):
                clean_tools, modified = self.engine.sanitize_tools_list(result["tools"])
                result["tools"] = clean_tools
                if modified:
                    self._write_audit(
                        {
                            "event": "tools_list_sanitized",
                            "modified_tools": modified,
                        }
                    )
                return json.dumps(msg, ensure_ascii=False)

        return stripped

    def run_stdio_loop(self, command: list[str]) -> int:
        """Spawn the wrapped MCP server and proxy JSON-RPC traffic over stdio."""
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None
        out_lock = threading.Lock()

        def _emit(line: str) -> None:
            with out_lock:
                sys.stdout.write(line.rstrip("\r\n") + "\n")
                sys.stdout.flush()

        def _pump_server() -> None:
            for server_line in proc.stdout:  # type: ignore[union-attr]
                filtered = self.handle_server_message(server_line)
                if filtered:
                    _emit(filtered)

        reader = threading.Thread(target=_pump_server, daemon=True)
        reader.start()

        try:
            for client_line in sys.stdin:
                forward, immediate = self.handle_client_message(client_line)
                if immediate is not None:
                    _emit(immediate)
                if forward is not None:
                    proc.stdin.write(forward.rstrip("\r\n") + "\n")
                    proc.stdin.flush()
        finally:
            if proc.stdin:
                proc.stdin.close()
            proc.wait()
            reader.join(timeout=2.0)

        return int(proc.returncode or 0)
