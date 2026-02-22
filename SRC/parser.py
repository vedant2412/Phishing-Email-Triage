from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import Parser
from typing import Dict, Optional


@dataclass
class ParsedEmail:
    """
    Normalized representation of an email for offline triage.

    - headers: lowercased header names mapped to a single string value
    - subject: subject line (best-effort)
    - from_addr: From header (best-effort)
    - reply_to: Reply-To header (best-effort)
    - return_path: Return-Path header (best-effort)
    - body_text: extracted text content (best-effort)
    - raw: original raw email text
    """
    headers: Dict[str, str]
    subject: str
    from_addr: str
    reply_to: str
    return_path: str
    body_text: str
    raw: str


def _safe_str(value: Optional[str]) -> str:
    return (value or "").strip()


def _collapse_headers(msg: Message) -> Dict[str, str]:
    """
    Convert email headers into a simple dictionary with lowercase keys.
    If a header appears multiple times, values are joined with " | ".
    """
    out: Dict[str, str] = {}
    for k, v in msg.items():
        key = (k or "").strip().lower()
        val = str(v).strip()
        if not key:
            continue
        if key in out and out[key]:
            out[key] = f"{out[key]} | {val}"
        else:
            out[key] = val
    return out


def _extract_body_text(msg: Message) -> str:
    """
    Extract a best-effort plaintext body.
    Prefers text/plain parts; falls back to text/html stripped lightly.
    """
    if msg.is_multipart():
        # Prefer text/plain
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype == "text/plain":
                return _decode_part(part)

        # Fallback: first text/html
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype == "text/html":
                html = _decode_part(part)
                return _very_light_html_to_text(html)

        return ""
    else:
        ctype = (msg.get_content_type() or "").lower()
        payload = _decode_part(msg)
        if ctype == "text/html":
            return _very_light_html_to_text(payload)
        return payload


def _decode_part(part: Message) -> str:
    """
    Decode a MIME part into text safely.
    """
    try:
        raw_bytes = part.get_payload(decode=True)
        if raw_bytes is None:
            # Some messages store payload already as str
            return _safe_str(part.get_payload())
        charset = part.get_content_charset() or "utf-8"
        return raw_bytes.decode(charset, errors="replace").strip()
    except Exception:
        # Fail safely
        return ""


def _very_light_html_to_text(html: str) -> str:
    """
    Minimal HTML to text conversion without external libraries.
    Not perfect, but good enough for offline scoring signals.
    """
    text = html

    # Remove common tags (very light)
    for token in ["<br>", "<br/>", "<br />", "</p>", "</div>", "</tr>", "</li>"]:
        text = text.replace(token, "\n")

    # Remove other tags crudely
    out = []
    in_tag = False
    for ch in text:
        if ch == "<":
            in_tag = True
            continue
        if ch == ">":
            in_tag = False
            continue
        if not in_tag:
            out.append(ch)

    cleaned = "".join(out)
    # Normalize whitespace
    cleaned = "\n".join(line.strip() for line in cleaned.splitlines() if line.strip())
    return cleaned.strip()


def parse_raw_email(raw_email: str) -> ParsedEmail:
    """
    Parse a raw RFC822 email string into ParsedEmail.

    Works for:
    - .eml content
    - raw email text with headers + body
    """
    # Use the standard library email parser with a modern policy
    msg = Parser(policy=policy.default).parsestr(raw_email)

    headers = _collapse_headers(msg)
    subject = _safe_str(headers.get("subject"))
    from_addr = _safe_str(headers.get("from"))
    reply_to = _safe_str(headers.get("reply-to"))
    return_path = _safe_str(headers.get("return-path"))

    body_text = _extract_body_text(msg)

    return ParsedEmail(
        headers=headers,
        subject=subject,
        from_addr=from_addr,
        reply_to=reply_to,
        return_path=return_path,
        body_text=body_text,
        raw=raw_email,
    )