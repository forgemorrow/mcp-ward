"""Tests for adversarial benchmark, reporters (SARIF/HTML), and CLI."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_ward import cli
from mcp_ward.eval.benchmark import format_eval_markdown, run_eval_suite
from mcp_ward.reporters import to_html, to_sarif
from mcp_ward.scanner import scan_path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_eval_suite_metrics():
    res = run_eval_suite()
    assert res.total_attacks == 8
    assert res.total_benign == 4
    assert res.baseline_asr == 1.0
    assert res.guarded_asr == 0.0
    assert res.defense_rate == 1.0
    assert res.false_positive_rate == 0.0
    md = format_eval_markdown(res)
    assert "Attack Defense Rate   : 100.0%" in md


def test_sarif_and_html_reporters():
    report = scan_path(REPO_ROOT / "examples" / "vulnerable_workspace")
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(report.findings)

    html_doc = to_html(report)
    assert "Grade F (100/100)" in html_doc
    # Cross-tool tag should be HTML-escaped rather than raw HTML tag
    assert "&lt;IMPORTANT&gt;" in html_doc


def test_cli_subcommands(tmp_path: Path):
    clean_dir = str(REPO_ROOT / "examples" / "clean_workspace")
    vuln_dir = str(REPO_ROOT / "examples" / "vulnerable_workspace")

    assert cli.main(["scan", clean_dir, "--fail-on", "LOW"]) == 0
    assert cli.main(["scan", vuln_dir, "--fail-on", "CRITICAL"]) == 1

    sarif_out = tmp_path / "report.sarif"
    assert cli.main(["scan", vuln_dir, "--format", "sarif", "--out", str(sarif_out)]) == 0
    assert json.loads(sarif_out.read_text(encoding="utf-8"))["version"] == "2.1.0"

    assert cli.main(["eval"]) == 0
    assert cli.main(["check-call", "add_numbers", "--args", '{"a": 1, "b": 2}']) == 0
    assert cli.main(["check-call", "send_http", "--args", '{"url": "https://api.example.com"}', "--taint-sensitive"]) == 2
