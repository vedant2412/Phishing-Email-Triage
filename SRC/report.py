from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .iocs import IOCs
from .parser import ParsedEmail
from .scoring import ScoreResult


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_headers_subset(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Keep a small, useful subset of headers to avoid dumping everything.
    """
    keep = [
        "from",
        "to",
        "subject",
        "date",
        "reply-to",
        "return-path",
        "message-id",
        "received",
        "content-type",
    ]
    out: Dict[str, str] = {}
    for k in keep:
        if k in headers and headers[k]:
            out[k] = headers[k]
    return out


def build_report_dict(email: ParsedEmail, iocs: IOCs, score: ScoreResult) -> Dict[str, Any]:
    return {
        "generated_at_utc": _utc_now_iso(),
        "classification": score.classification,
        "risk_score": score.score,
        "reasons": score.reasons,
        "headers": _safe_headers_subset(email.headers),
        "from_addr": email.from_addr,
        "reply_to": email.reply_to,
        "return_path": email.return_path,
        "subject": email.subject,
        "iocs": {
            "urls": iocs.urls,
            "domains": iocs.domains,
            "ips": iocs.ips,
            "hashes": iocs.hashes,
        },
        "body_preview": (email.body_text[:500] + "...") if len(email.body_text) > 500 else email.body_text,
    }


def write_json_report(out_dir: Path, report: Dict[str, Any]) -> Path:
    out_path = out_dir / "report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def write_markdown_report(out_dir: Path, report: Dict[str, Any]) -> Path:
    out_path = out_dir / "report.md"

    lines: List[str] = []
    lines.append("# Phishing Triage Report")
    lines.append("")
    lines.append(f"- Generated (UTC): {report.get('generated_at_utc','')}")
    lines.append(f"- Classification: **{report.get('classification','')}**")
    lines.append(f"- Risk Score: **{report.get('risk_score','')} / 100**")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"**Subject:** {report.get('subject','')}")
    lines.append(f"**From:** {report.get('from_addr','')}")
    lines.append(f"**Reply-To:** {report.get('reply_to','')}")
    lines.append(f"**Return-Path:** {report.get('return_path','')}")
    lines.append("")

    lines.append("## Reasons")
    lines.append("")
    reasons = report.get("reasons", []) or []
    if reasons:
        for r in reasons:
            lines.append(f"- {r}")
    else:
        lines.append("- No high-risk indicators detected.")
    lines.append("")

    lines.append("## Extracted IOCs")
    lines.append("")
    iocs = report.get("iocs", {}) or {}
    lines.append(f"- URLs: {len(iocs.get('urls', []))}")
    lines.append(f"- Domains: {len(iocs.get('domains', []))}")
    lines.append(f"- IPs: {len(iocs.get('ips', []))}")
    lines.append(f"- Hashes: {len(iocs.get('hashes', []))}")
    lines.append("")

    if iocs.get("urls"):
        lines.append("### URLs")
        lines.append("")
        for u in iocs["urls"]:
            lines.append(f"- {u}")
        lines.append("")

    if iocs.get("domains"):
        lines.append("### Domains")
        lines.append("")
        for d in iocs["domains"]:
            lines.append(f"- {d}")
        lines.append("")

    if iocs.get("ips"):
        lines.append("### IPs")
        lines.append("")
        for ip in iocs["ips"]:
            lines.append(f"- {ip}")
        lines.append("")

    if iocs.get("hashes"):
        lines.append("### Hashes")
        lines.append("")
        for h in iocs["hashes"]:
            lines.append(f"- {h}")
        lines.append("")

    lines.append("## Headers (Subset)")
    lines.append("")
    headers = report.get("headers", {}) or {}
    if headers:
        for k, v in headers.items():
            lines.append(f"- **{k}**: {v}")
    else:
        lines.append("- (No headers captured)")
    lines.append("")

    lines.append("## Body Preview")
    lines.append("")
    body_preview = report.get("body_preview", "") or ""
    if body_preview:
        lines.append("```")
        lines.append(body_preview)
        lines.append("```")
    else:
        lines.append("_No body text extracted._")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def write_reports(out_dir: Path, email: ParsedEmail, iocs: IOCs, score: ScoreResult) -> Dict[str, Path]:
    report = build_report_dict(email, iocs, score)
    json_path = write_json_report(out_dir, report)
    md_path = write_markdown_report(out_dir, report)
    return {"json": json_path, "md": md_path}