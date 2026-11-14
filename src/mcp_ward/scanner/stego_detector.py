"""Detection of hidden instructions, Unicode smuggling, and tool poisoning."""

from __future__ import annotations

import re

from ..models import Finding, Severity

ZERO_WIDTH_CHARS = {
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (mid-document)
}

BIDI_CHARS = {
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
}

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_MD_COMMENT_RE = re.compile(r"^\[(?://|comment)\]:\s*(?:#|<>)\s*\((.+)\)$", re.MULTILINE)
_IMPORTANT_BLOCK_RE = re.compile(r"<\s*important\s*>(.*?)<\s*/\s*important\s*>", re.DOTALL | re.IGNORECASE)

_POISON_DIRECTIVE_RE = re.compile(
    r"(ignore\s+(?:all\s+)?previous|do\s+not\s+tell|do\s+not\s+mention|"
    r"silently|without\s+informing|read\s+~?/?\.ssh|id_rsa|\.env\b|"
    r"https?://|webhook|curl\s+|exfiltrat|system\s+prompt|override\s+instructions)",
    re.IGNORECASE,
)

_COERCIVE_SHADOW_RE = re.compile(
    r"(<\s*important\s*>|before\s+calling\b|must\s+first\s+call\b|"
    r"do\s+not\s+mention\s+to\s+the\s+user|do\s+not\s+inform\s+the\s+user|"
    r"never\s+tell\s+the\s+user|exfiltrat|id_rsa)",
    re.IGNORECASE,
)


def decode_unicode_tags(text: str) -> str:
    """Decode invisible Unicode Tag block characters (U+E0020..U+E007E) to ASCII."""
    chars: list[str] = []
    for ch in text:
        code = ord(ch)
        if 0xE0020 <= code <= 0xE007E:
            chars.append(chr(code - 0xE0000))
    return "".join(chars)


def _line_number_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _has_unicode_tag(text: str) -> bool:
    return any(0xE0000 <= ord(ch) <= 0xE007F for ch in text)


def scan_text_for_poisoning(
    text: str,
    file_path: str,
    base_line: int = 1,
) -> list[Finding]:
    """Scan prompt markdown, JSON descriptions, or docstrings for poisoning."""
    findings: list[Finding] = []
    if not text:
        return findings

    lines = text.splitlines()
    for idx, line_text in enumerate(lines):
        line_no = base_line + idx

        # Ignore optional UTF-8 BOM at index 0 of line 1 only
        inspect_line = line_text[1:] if (idx == 0 and line_text.startswith("\ufeff")) else line_text
        has_zw = any(ch in ZERO_WIDTH_CHARS for ch in inspect_line)
        has_tags = _has_unicode_tag(inspect_line)
        if has_zw or has_tags:
            decoded = decode_unicode_tags(inspect_line)
            snippet = (
                f"Decoded Unicode Tag payload: {decoded}"
                if decoded
                else "Invisible zero-width / Unicode tag characters present"
            )
            findings.append(
                Finding(
                    rule_id="MW-STEG-001",
                    title="Invisible Unicode Steganography Detected",
                    severity=Severity.CRITICAL,
                    category="steganography",
                    file_path=file_path,
                    line=line_no,
                    snippet=snippet[:200],
                    recommendation=(
                        "Strip zero-width and Unicode Tag codepoints (U+200B..U+2060, "
                        "U+E0000..U+E007F) before loading prompts or tool schemas."
                    ),
                    metadata={"decoded_payload": decoded} if decoded else {},
                )
            )

        if any(ch in BIDI_CHARS for ch in line_text):
            findings.append(
                Finding(
                    rule_id="MW-STEG-002",
                    title="Unicode Bidirectional Override Character Detected",
                    severity=Severity.CRITICAL,
                    category="steganography",
                    file_path=file_path,
                    line=line_no,
                    snippet="Bidi control character (e.g. U+202E/U+2066) alters visual text order",
                    recommendation="Remove all Unicode Bidi override and isolate characters.",
                )
            )

    # Multi-line HTML & markdown comment checks
    masked_spans: list[tuple[int, int]] = []
    for pattern in (_HTML_COMMENT_RE, _MD_COMMENT_RE):
        for match in pattern.finditer(text):
            body = match.group(1).strip()
            if _POISON_DIRECTIVE_RE.search(body):
                line_no = base_line + _line_number_at(text, match.start()) - 1
                masked_spans.append((match.start(), match.end()))
                findings.append(
                    Finding(
                        rule_id="MW-POISON-001",
                        title="Hidden Comment Prompt Poisoning Detected",
                        severity=Severity.CRITICAL,
                        category="prompt-poisoning",
                        file_path=file_path,
                        line=line_no,
                        snippet=" ".join(body.split())[:180],
                        recommendation=(
                            "Remove hidden HTML/Markdown comments containing operational "
                            "or exfiltration instructions from tool descriptions and skills."
                        ),
                    )
                )

    # Check visible text (excluding already-flagged comment spans) for coercive shadowing
    visible_chars = list(text)
    for start, end in masked_spans:
        for pos in range(start, end):
            if visible_chars[pos] != "\n":
                visible_chars[pos] = " "
    visible_text = "".join(visible_chars)

    shadow_chars = list(visible_text)
    for match in _IMPORTANT_BLOCK_RE.finditer(visible_text):
        body = " ".join(match.group(1).split())
        findings.append(
            Finding(
                rule_id="MW-POISON-002",
                title="Coercive Cross-Tool Shadowing Directive Detected",
                severity=Severity.CRITICAL,
                category="tool-shadowing",
                file_path=file_path,
                line=base_line + _line_number_at(visible_text, match.start()) - 1,
                snippet=(f"<IMPORTANT> {body}" if body else "<IMPORTANT>")[:180],
                recommendation=(
                    "Audit cross-tool directives (<IMPORTANT>, forced pre-calls, "
                    "user-concealment phrasing) and strip deceptive instructions."
                ),
            )
        )
        for pos in range(match.start(), match.end()):
            if shadow_chars[pos] != "\n":
                shadow_chars[pos] = " "

    remaining_visible = "".join(shadow_chars)
    for idx, line_text in enumerate(remaining_visible.splitlines()):
        match = _COERCIVE_SHADOW_RE.search(line_text)
        if match:
            findings.append(
                Finding(
                    rule_id="MW-POISON-002",
                    title="Coercive Cross-Tool Shadowing Directive Detected",
                    severity=Severity.CRITICAL,
                    category="tool-shadowing",
                    file_path=file_path,
                    line=base_line + idx,
                    snippet=line_text.strip()[:180],
                    recommendation=(
                        "Audit cross-tool directives (<IMPORTANT>, forced pre-calls, "
                        "user-concealment phrasing) and strip deceptive instructions."
                    ),
                )
            )

    return findings
