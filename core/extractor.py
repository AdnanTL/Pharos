"""
PHAROS — Extractor
Extrait tous les IOCs du contenu de l'email
"""

import re
from urllib.parse import urlparse
from dataclasses import dataclass, field


URL_RE = re.compile(r'https?://[^\s\'"<>)\]\[}{,]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

COMMON_BENIGN_ROOTS = {
    "google.com", "gmail.com", "googleusercontent.com",
    "microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com",
    "apple.com", "amazon.com", "icloud.com", "yahoo.com",
    "facebook.com", "instagram.com", "linkedin.com",
    "youtube.com", "x.com", "twitter.com", "whatsapp.com",
    "cloudflare.com", "docusign.net", "dropbox.com",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".link",
    ".online", ".site", ".website", ".store", ".tk",
    ".ml", ".ga", ".cf", ".gq",
}

PHISHING_KEYWORDS = [
    "verify", "secure", "update", "account", "login", "signin",
    "confirm", "banking", "payment", "password", "credential",
    "authenticate", "suspended", "unusual", "recover", "unlock",
    "alert", "notice", "warning",
]

SUSPICIOUS_HTML = [
    r'<form[^>]+action=["\'][^"\']*(?:http|ftp)',
    r'<input[^>]+type=["\']password["\']',
    r'javascript:',
    r'document\.cookie',
    r'window\.location',
    r'eval\(',
]

BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple",
    "netflix", "facebook", "instagram", "linkedin", "outlook",
    "dropbox", "docusign", "dhl", "fedex", "ups",
]


@dataclass
class Observables:
    urls: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    suspicious_patterns: list = field(default_factory=list)
    sender_domain: str = ""
    sender_root_domain: str = ""
    url_count: int = 0
    external_domain_count: int = 0


def extract(text: str, html: str = "", from_addr: str = "") -> Observables:
    obs = Observables()
    combined = (text or "") + "\n" + (html or "")

    sender_domain = _extract_email_domain(from_addr)
    sender_root = _root_domain(sender_domain) if sender_domain else ""
    obs.sender_domain = sender_domain
    obs.sender_root_domain = sender_root

    seen_urls = set()
    for url in URL_RE.findall(combined):
        url = url.rstrip(".,;:)'\"")
        if url not in seen_urls:
            seen_urls.add(url)
            obs.urls.append(url)

    seen_ips = set()
    for ip in IP_RE.findall(combined):
        if ip not in seen_ips and not _is_private_ip(ip):
            seen_ips.add(ip)
            obs.ips.append(ip)

    seen_emails = set()
    for em in EMAIL_RE.findall(combined):
        if em not in seen_emails and em.lower() != (from_addr or "").lower():
            seen_emails.add(em)
            obs.emails.append(em)

    seen_domains = set()
    external_roots = set()
    for url in obs.urls:
        try:
            domain = urlparse(url).netloc.lower().split(":")[0]
            root = _root_domain(domain)
            if root and root not in seen_domains:
                seen_domains.add(root)
                obs.domains.append(root)
            if root and sender_root and root != sender_root:
                external_roots.add(root)
        except Exception:
            pass

    obs.url_count = len(obs.urls)
    obs.external_domain_count = len(external_roots)

    if html:
        for pattern in SUSPICIOUS_HTML:
            if re.search(pattern, html, re.IGNORECASE):
                obs.suspicious_patterns.append(pattern)

    return obs


def score_url(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]
    root = _root_domain(domain)
    flags = []
    score = 0

    if not domain:
        return {"score": 0, "flags": []}

    if root in COMMON_BENIGN_ROOTS:
        return {"score": 0, "flags": []}

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"TLD suspect : {tld}")
            score += 18
            break

    for kw in PHISHING_KEYWORDS:
        if kw in url.lower():
            flags.append(f"Mot-clé sensible dans l'URL : '{kw}'")
            score += 8
            break

    if IP_RE.fullmatch(domain):
        flags.append("IP utilisée à la place d'un domaine")
        score += 35

    if len(domain.split(".")) > 4:
        flags.append(f"Trop de sous-domaines ({len(domain.split('.'))} niveaux)")
        score += 10

    for brand in BRANDS:
        if brand in domain and root != f"{brand}.com":
            flags.append(f"Marque connue présente dans un domaine non canonique : '{brand}'")
            score += 35
            break

    if len(url) > 220:
        flags.append(f"URL longue ({len(url)} caractères)")
        score += 5

    if url.count("%") > 4:
        flags.append("Encodage URL élevé")
        score += 10

    return {"score": min(100, score), "flags": flags}


def _extract_email_domain(addr: str) -> str:
    m = re.search(r'@([\w.\-]+)', addr or "")
    return m.group(1).lower() if m else ""


def _root_domain(domain: str) -> str:
    parts = (domain or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "")


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10 or a == 127 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168)
        )
    except ValueError:
        return True
