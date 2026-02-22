"""
Phishing Email Triage CLI

Usage examples:
  python -m SRC.phishtriage.cli --eml "Sample Emails/sample_phish.eml"
  python -m SRC.phishtriage.cli --text "Sample Emails/email.txt"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .features import detect_features
from .iocs import extract_iocs
from .parser import parse_raw_email
from .report import write_reports
from .scoring import score_email

console = Console()


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        console.print(f"[red]File not found:[/red] {path}")
        sys.exit(2)


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phish-triage",
        description="Offline phishing email triage: parse email, score risk, extract IOCs, generate reports.",
    )

    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--eml", type=str, help="Path to a raw .eml email file (RFC822).")
    group.add_argument("--text", type=str, help="Path to a text file containing email headers + body.")

    p.add_argument(
        "--out",
        type=str,
        default="output",
        help="Output directory for generated reports (default: output).",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal console output (still writes reports).",
    )
    return p


def _print_summary(score, features, iocs) -> None:
    console.print(f"[bold]Risk Score:[/bold] {score.score} / 100")
    console.print(f"[bold]Classification:[/bold] {score.classification}")
    console.print("")

    table = Table(title="Detected Indicators", show_lines=False)
    table.add_column("Severity", justify="center")
    table.add_column("Indicator")
    if features:
        for f in features:
            table.add_row(str(f.severity), f.description)
    else:
        table.add_row("-", "No high-risk indicators detected.")
    console.print(table)

    console.print("")
    ioc_table = Table(title="Extracted IOCs", show_lines=False)
    ioc_table.add_column("Type")
    ioc_table.add_column("Count", justify="right")
    ioc_table.add_row("URLs", str(len(iocs.urls)))
    ioc_table.add_row("Domains", str(len(iocs.domains)))
    ioc_table.add_row("IPs", str(len(iocs.ips)))
    ioc_table.add_row("Hashes", str(len(iocs.hashes)))
    console.print(ioc_table)


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.eml:
        in_path = Path(args.eml)
        raw_email = _read_text_file(in_path)
        input_label = f"EML: {in_path}"
    else:
        in_path = Path(args.text)
        raw_email = _read_text_file(in_path)
        input_label = f"TEXT: {in_path}"

    if not args.quiet:
        console.print(Panel.fit("Phishing Email Triage CLI", subtitle=input_label))

    # 1) Parse email into normalized structure
    parsed = parse_raw_email(raw_email)

    # 2) Extract IOCs from headers + body (offline)
    combined_text = "\n".join(
        [
            parsed.subject,
            parsed.from_addr,
            parsed.reply_to,
            parsed.return_path,
            parsed.body_text,
        ]
    )
    iocs = extract_iocs(combined_text)

    # 3) Detect phishing indicators (features)
    features = detect_features(parsed, iocs)

    # 4) Convert features into score + classification
    score = score_email(features)

    # 5) Write reports (JSON + Markdown)
    paths = write_reports(out_dir, parsed, iocs, score)

    if not args.quiet:
        _print_summary(score, features, iocs)
        console.print("")
        console.print("[bold]Reports written:[/bold]")
        console.print(f"- JSON: {paths['json']}")
        console.print(f"- Markdown: {paths['md']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())