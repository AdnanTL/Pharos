"""
PHAROS — Scoring Engine
Scoring global avec séparation risk_score / benign_score.
"""

from dataclasses import dataclass, field
import re


@dataclass
class PhishingScore:
    score: int = 0
    risk_score: int = 0
    benign_score: int = 0
    level: str = "LOW"
    verdict: str = "Probablement sain"
    indicators: list = field(default_factory=list)
    strong_signals: list = field(default_factory=list)
    benign_signals: list = field(default_factory=list)
    color: str = "#44cc44"

    def to_dict(self):
        return {
            "score": self.score,
            "risk_score": self.risk_score,
            "benign_score": self.benign_score,
            "level": self.level,
            "verdict": self.verdict,
            "indicators": self.indicators,
            "strong_signals": self.strong_signals,
            "benign_signals": self.benign_signals,
            "color": self.color,
        }


def calculate_score(parsed_email, observables,
                    domain_results, ip_results,
                    url_scores, redirect_chains,
                    reputation_features=None):

    reputation_features = reputation_features or {}

    risk_score = 0
    benign_score = 0
    indicators = []
    strong_signals = []
    benign_signals = []

    from_dom = _extract_domain(parsed_email.from_addr) or ""
    from_root = _root_domain(from_dom)
    reply_dom = _extract_domain(parsed_email.reply_to) if parsed_email.reply_to else ""
    reply_root = _root_domain(reply_dom) if reply_dom else ""
    return_dom = _extract_domain(parsed_email.return_path) if parsed_email.return_path else ""
    return_root = _root_domain(return_dom) if return_dom else ""

    if parsed_email.spf == "pass":
        benign_score += 10
        benign_signals.append("SPF PASS")
    elif parsed_email.spf in ("fail", "softfail"):
        risk_score += 30
        strong_signals.append(f"SPF {parsed_email.spf.upper()}")
        indicators.append(f"SPF {parsed_email.spf.upper()} — serveur non autorisé")
    elif parsed_email.spf == "none":
        risk_score += 3
        indicators.append("SPF absent")

    if parsed_email.dkim == "pass":
        benign_score += 10
        benign_signals.append("DKIM PASS")
    elif parsed_email.dkim == "fail":
        risk_score += 25
        strong_signals.append("DKIM FAIL")
        indicators.append("DKIM FAIL — intégrité potentiellement compromise")
    elif parsed_email.dkim == "none":
        risk_score += 3
        indicators.append("DKIM absent")

    if parsed_email.dmarc == "pass":
        benign_score += 12
        benign_signals.append("DMARC PASS")
    elif parsed_email.dmarc == "fail":
        risk_score += 25
        strong_signals.append("DMARC FAIL")
        indicators.append("DMARC FAIL — politique non respectée")
    elif parsed_email.dmarc == "none":
        risk_score += 2
        indicators.append("DMARC absent")

    if from_root and reply_root and from_root != reply_root:
        risk_score += 25
        strong_signals.append("Reply-To incohérent")
        indicators.append(f"Reply-To incohérent : FROM={from_root}, REPLY-TO={reply_root}")

    if from_root and return_root and from_root != return_root:
        risk_score += 10
        indicators.append(f"Return-Path différent : {return_root} ≠ {from_root}")

    urgent_words = [
        "urgent", "action required", "verify", "suspended", "blocked",
        "unusual activity", "confirm", "update your", "your account",
        "immediately", "warning", "alert", "invoice", "overdue",
    ]
    subject_lower = (parsed_email.subject or "").lower()
    for word in urgent_words:
        if word in subject_lower:
            risk_score += 4
            indicators.append(f"Sujet incitatif : '{word}'")
            break

    suspicious_url_count = 0
    for us in url_scores:
        if us["score"] >= 60:
            suspicious_url_count += 1
            risk_score += 18
            for flag in us["flags"]:
                indicators.append(f"URL suspecte : {flag}")
        elif us["score"] >= 30:
            risk_score += 6
            for flag in us["flags"]:
                indicators.append(f"URL atypique : {flag}")

    if suspicious_url_count >= 2:
        strong_signals.append("Plusieurs URLs suspectes")

    if getattr(observables, "url_count", 0) >= 8:
        risk_score += 4
        indicators.append(f"Email très riche en liens ({observables.url_count})")

    if getattr(observables, "external_domain_count", 0) >= 4:
        risk_score += 5
        indicators.append(f"Multiples domaines externes ({observables.external_domain_count})")

    for dr in domain_results:
        if dr.get("age_days") is not None and dr["age_days"] < 21:
            risk_score += 20
            strong_signals.append(f"Domaine récent : {dr['domain']}")
            indicators.append(f"Domaine récent : {dr['domain']} créé il y a {dr['age_days']} jours")

        if dr.get("vt_malicious", 0) > 0:
            risk_score += 35
            strong_signals.append(f"VirusTotal positif : {dr['domain']}")
            indicators.append(
                f"VirusTotal : {dr['domain']} signalé par {dr['vt_malicious']}/{dr.get('vt_total', 0)} moteurs"
            )

        if dr.get("dns_valid") is True:
            benign_score += 2

    for ir in ip_results:
        if ir.get("abuse_score", 0) >= 70:
            risk_score += 25
            strong_signals.append(f"IP à fort abuse score : {ir['ip']}")
            indicators.append(f"IP {ir['ip']} : abuse score élevé ({ir['abuse_score']}/100)")
        elif ir.get("abuse_score", 0) >= 30:
            risk_score += 8
            indicators.append(f"IP {ir['ip']} : abuse score modéré ({ir['abuse_score']}/100)")

        if ir.get("is_tor"):
            risk_score += 30
            strong_signals.append(f"IP Tor : {ir['ip']}")
            indicators.append(f"IP {ir['ip']} : nœud de sortie Tor")

    for chain in redirect_chains:
        if len(chain) > 4:
            risk_score += 8
            indicators.append(f"Chaîne de redirections longue ({len(chain)} sauts)")

    dangerous_exts = [".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".ps1", ".scr", ".msi", ".hta", ".reg"]
    for att in getattr(parsed_email, "attachments", []):
        fname = (att.filename or "").lower()

        if fname.endswith(".pdf") or fname.endswith(".txt") or fname.endswith(".png") or fname.endswith(".jpg") or fname.endswith(".jpeg"):
            benign_score += 2

        for ext in dangerous_exts:
            if fname.endswith(ext):
                risk_score += 40
                strong_signals.append(f"Pièce jointe dangereuse : {att.filename}")
                indicators.append(f"Pièce jointe dangereuse : {att.filename}")
                break

        parts = fname.split(".")
        if len(parts) > 2 and parts[-2] in ("exe", "vbs", "bat", "js", "scr"):
            risk_score += 45
            strong_signals.append(f"Double extension : {att.filename}")
            indicators.append(f"Double extension suspecte : {att.filename}")

    if observables.suspicious_patterns:
        risk_score += 20
        strong_signals.append("HTML suspect")
        indicators.append(
            f"{len(observables.suspicious_patterns)} pattern(s) HTML suspects détectés"
        )

    seen_count = reputation_features.get("seen_count", 0)
    benign_ratio = reputation_features.get("benign_ratio", 0.0)
    malicious_ratio = reputation_features.get("malicious_ratio", 0.0)

    if reputation_features.get("is_established_sender"):
        benign_score += 8
        benign_signals.append("Expéditeur déjà observé")

    if reputation_features.get("is_historically_benign"):
        benign_score += 18
        benign_signals.append("Historique local bénin")

    if reputation_features.get("is_historically_risky"):
        risk_score += 20
        strong_signals.append("Historique local risqué")
        indicators.append("Historique local : expéditeur déjà signalé comme risqué")

    if seen_count == 0:
        indicators.append("Expéditeur inconnu localement")
    else:
        indicators.append(
            f"Réputation locale : seen={seen_count}, benign_ratio={benign_ratio}, malicious_ratio={malicious_ratio}"
        )

    risk_score = max(0, min(100, risk_score))
    benign_score = max(0, min(100, benign_score))

    final_score = max(0, min(100, risk_score - int(benign_score * 0.7)))
    strong_count = len(set(strong_signals))

    if strong_count >= 2 and final_score >= 55:
        level = "CRITICAL"
        verdict = "Phishing probable — plusieurs signaux forts cumulés"
        color = "#ff4444"
    elif strong_count >= 1 and final_score >= 40:
        level = "HIGH"
        verdict = "Menace probable — vérification urgente requise"
        color = "#ff8800"
    elif final_score >= 18:
        level = "MEDIUM"
        verdict = "Ambigu ou atypique — analyse manuelle recommandée"
        color = "#ffcc00"
    else:
        level = "LOW"
        verdict = "Probablement sain"
        color = "#44cc44"

    if level in ("HIGH", "CRITICAL") and strong_count == 0:
        level = "MEDIUM"
        verdict = "Atypique mais sans signal fort confirmé"
        color = "#ffcc00"

    return PhishingScore(
        score=final_score,
        risk_score=risk_score,
        benign_score=benign_score,
        level=level,
        verdict=verdict,
        indicators=indicators,
        strong_signals=list(dict.fromkeys(strong_signals)),
        benign_signals=list(dict.fromkeys(benign_signals)),
        color=color,
    )


def _extract_domain(addr: str):
    m = re.search(r'@([\w.\-]+)', addr or "")
    return m.group(1).lower() if m else None


def _root_domain(domain: str):
    if not domain:
        return None
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain
