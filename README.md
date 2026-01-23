# Phishing-Email-Triage

## Overview

Phishing emails remain one of the most common initial access vectors in real-world security incidents.
This project is a command-line phishing email triage tool that analyzes raw email content and headers to determine whether an email is legitimate or potentially malicious, while clearly explaining why.
The tool mimics how a SOC analyst performs first-level phishing triage by identifying common phishing indicators, assigning a risk score, and extracting relevant indicators of compromise (IOCs).

## What This Tool Does:

- Given a raw email file (.eml) or email text, the tool:
- Parses email headers and body content
- Identifies common phishing indicators such as:
- Sender domain mismatches (From vs Reply-To)
- Suspicious or obfuscated URLs
- Use of IP addresses instead of domains
- Urgent or coercive language patterns
- Suspicious attachment indicators (double extensions, macro keywords)
- Assigns a phishing risk score (0–100) based on weighted heuristics

Classifies the email as:
- Safe
- Suspicious
- Likely Phishing
- Extracts Indicators of Compromise (IOCs):
- URLs
- Domains
- IP addresses
- Hashes (if present)

Generates structured triage output in:
- Human-readable console output
- JSON report
- Markdown incident summary




## Why This Project Exists

Most phishing detection tools operate as black boxes.
This project focuses on explainability and analyst-friendly output, ensuring every score is backed by clear evidence.

It demonstrates:

- Practical SOC-style email triage workflows
- Defensive security thinking rather than theoretical detection
- Automation that assists analysts instead of replacing judgment
