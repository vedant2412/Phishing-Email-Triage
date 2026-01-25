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


## Installation

This project is designed to run easily in GitHub Codespaces or any Python 3 environment.

>git clone https://github.com/vedant2412/phish-triage-cli.git
>
>cd phish-triage-cli
>
>pip install -r requirements.txt


## Detection Logic (High Level)

The scoring system uses rule-based heuristics commonly applied in enterprise phishing triage:

- Header inconsistencies
- Domain reputation signals (structure-based, not external lookups)
- URL obfuscation techniques
- Linguistic indicators of social engineering
- Attachment naming patterns

Each indicator contributes to a cumulative risk score, producing a final classification.


## Disclaimer

This project is for educational and practice purposes only.
It does not send network traffic, interact with live systems, or perform exploitation.
