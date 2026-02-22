from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Set, Tuple
from urllib.parse import urlparse

import tldextract


# Basic URL regex: good enough for offline triage (no network calls)
URL_RE = re.compile(
    r"""(?ix)
    \b(
        https?://[^\s<>"'()]+
    )\b
    """
)

# Naked domains (very conservative; avoids matching too much random text)
DOMAIN_RE = re.compile(
    r"""(?ix)
    \b(
        (?:[a-z0-9-]+\.)+(?:[a-z]{2,})
    )\b
    """
)

IPV4_RE = re.compile(
    r"""(?x)
    \b(
        (?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}
        (?:25[0-5]|2[0-4]\d|1?\d?\d)
    )\b
    """
)

MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


@dataclass
class IOCs:
    urls: List[str]
    domains: List[str]
    ips: List[str]
    hashes: List[str]


def _normalize_url(u: str) -> str:
    # Trim trailing punctuation common in emails
    return u.strip().strip(").,;:]!?'\"")


def _domain_from_url(u: str) -> str:
    try:
        parsed = urlparse(u)
        host = (parsed.hostname or "").strip().lower()
        return host
    except Exception:
        return ""


def _is_likely_domain(d: str) -> bool:
    d = (d or "").strip().lower()
    if not d or "@" in d:
        return False
    # avoid obvious false positives
    if d.endswith(".local") or d.endswith(".lan"):
        return False
    # parse using tldextract to ensure it has a suffix
    ext = tldextract.extract(d)
    return bool(ext.domain and ext.suffix)


def _unique_sorted(items: Set[str]) -> List[str]:
    return sorted(items)


def extract_iocs(text: str) -> IOCs:
    """
    Extract IOCs from text safely (offline):
    - URLs (http/https)
    - Domains (from URLs + naked domains in text)
    - IPv4 addresses
    - Hashes (MD5/SHA1/SHA256)
    """
    if not text:
        return IOCs(urls=[], domains=[], ips=[], hashes=[])

    urls_set: Set[str] = set()
    domains_set: Set[str] = set()
    ips_set: Set[str] = set()
    hashes_set: Set[str] = set()

    # URLs
    for m in URL_RE.finditer(text):
        url = _normalize_url(m.group(1))
        if url:
            urls_set.add(url)
            host = _domain_from_url(url)
            if host and _is_likely_domain(host):
                domains_set.add(host)

    # Naked domains (may include the same domains already added)
    for m in DOMAIN_RE.finditer(text):
        d = m.group(1).strip().lower().strip(").,;:]!?'\"")
        if _is_likely_domain(d):
            domains_set.add(d)

    # IPs
    for m in IPV4_RE.finditer(text):
        ips_set.add(m.group(1))

    # Hashes
    for m in MD5_RE.finditer(text):
        hashes_set.add(m.group(0).lower())
    for m in SHA1_RE.finditer(text):
        hashes_set.add(m.group(0).lower())
    for m in SHA256_RE.finditer(text):
        hashes_set.add(m.group(0).lower())

    return IOCs(
        urls=_unique_sorted(urls_set),
        domains=_unique_sorted(domains_set),
        ips=_unique_sorted(ips_set),
        hashes=_unique_sorted(hashes_set),
    )