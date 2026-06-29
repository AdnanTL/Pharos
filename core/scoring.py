"""
PHAROS — Scoring Engine
Scoring global avec séparation risk_score / benign_score.
Version renforcée pour éviter les faux LOW sur mails suspects
et être un peu plus stricte sur les mails avec pièce jointe.
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


def calculate_score(
    parsed_email,
    observables,
    domain_results,
    ip_results,
    url_scores,
    redirect_chains,
    reputation_features=None,
):
    reputation_features = reputation_features or {}

    risk_score = 0
    benign_score = 0
    indicators = []
    strong_signals = []
    benign_signals = []

    from_dom = _extract_domain(getattr(parsed_email, "from_addr", "")) or ""
    from_root = _root_domain(from_dom)
    reply_dom = _extract_domain(getattr(parsed_email, "reply_to", "")) if getattr(parsed_email, "reply_to", None) else ""
    reply_root = _root_domain(reply_dom) if reply_dom else ""
    return_dom = _extract_domain(getattr(parsed_email, "return_path", "")) if getattr(parsed_email, "return_path", None) else ""
    return_root = _root_domain(return_dom) if return_dom else ""

    subject_lower = _safe_lower(getattr(parsed_email, "subject", ""))
    body_lower = _safe_lower(
        getattr(parsed_email, "body_text", None)
        or getattr(parsed_email, "text_body", None)
        or getattr(parsed_email, "body", None)
        or ""
    )

    attachments = getattr(parsed_email, "attachments", []) or []
    attachment_count = len(attachments)

    suspicious_url_count = 0
    medium_url_count = 0
    suspicious_keyword_hits = 0
    body_keyword_hits = 0
    attachment_risk_hits = 0
    sender_identity_mismatch = False

    # ---------------------------
    # Authentication
    # ---------------------------
    spf = _safe_lower(getattr(parsed_email, "spf", "none"))
    dkim = _safe_lower(getattr(parsed_email, "dkim", "none"))
    dmarc = _safe_lower(getattr(parsed_email, "dmarc", "none"))

    if spf == "pass":
        benign_score += 3
        benign_signals.append("SPF PASS")
    elif spf in ("fail", "softfail"):
        risk_score += 30
        strong_signals.append(f"SPF {spf.upper()}")
        indicators.append(f"SPF {spf.upper()} — serveur non autorisé")
    elif spf == "none":
        risk_score += 5
        indicators.append("SPF absent")

    if dkim == "pass":
        benign_score += 3
        benign_signals.append("DKIM PASS")
    elif dkim == "fail":
        risk_score += 25
        strong_signals.append("DKIM FAIL")
        indicators.append("DKIM FAIL — intégrité potentiellement compromise")
    elif dkim == "none":
        risk_score += 5
        indicators.append("DKIM absent")

    if dmarc == "pass":
        benign_score += 4
        benign_signals.append("DMARC PASS")
    elif dmarc == "fail":
        risk_score += 30
        strong_signals.append("DMARC FAIL")
        indicators.append("DMARC FAIL — politique non respectée")
    elif dmarc == "none":
        risk_score += 5
        indicators.append("DMARC absent")

    # ---------------------------
    # Identity consistency
    # ---------------------------
    if from_root and reply_root and from_root != reply_root:
        sender_identity_mismatch = True
        risk_score += 25
        strong_signals.append("Reply-To incohérent")
        indicators.append(f"Reply-To incohérent : FROM={from_root}, REPLY-TO={reply_root}")

    if from_root and return_root and from_root != return_root:
        risk_score += 12
        indicators.append(f"Return-Path différent : {return_root} ≠ {from_root}")

    # ---------------------------
    # Subject / body intent
    # ---------------------------
    high_risk_keywords = [
        "verify", "verification", "confirm", "confirmation",
        "suspended", "blocked", "urgent", "immediately",
        "action required", "unusual activity", "security alert",
        "password", "reset", "login", "document", "invoice",
        "payment", "delivery", "parcel", "package", "colis",
        "livraison", "amende", "douane", "customs", "failed delivery",
        "account locked", "account suspended", "your account",
        "mise à jour", "mettre à jour", "veuillez confirmer",
        "vérification", "votre colis", "colis en attente",
        "livraison impossible", "tentative de livraison",
    ]

    medium_risk_keywords = [
        "click here", "open", "review", "update", "notice", "message",
        "account", "support", "notification", "proof", "attachment",
        "ouvrir", "consulter", "voir", "document joint",
    ]

    for word in high_risk_keywords:
        if word in subject_lower:
            risk_score += 8
            suspicious_keyword_hits += 1
            indicators.append(f"Sujet à risque : '{word}'")

    for word in medium_risk_keywords:
        if word in subject_lower:
            risk_score += 4
            suspicious_keyword_hits += 1
            indicators.append(f"Sujet incitatif : '{word}'")

    body_keywords = [
        "verify", "confirm", "login", "password", "delivery",
        "parcel", "colis", "livraison", "click here", "urgent",
        "document", "invoice", "payment", "account", "reset",
        "mettre à jour", "vérifier", "confirmer",
    ]
    for word in body_keywords:
        if word in body_lower:
            body_keyword_hits += 1

    if body_keyword_hits >= 3:
        risk_score += 12
        indicators.append(f"Contenu textuel très incitatif ({body_keyword_hits} marqueurs)")
    elif body_keyword_hits == 2:
        risk_score += 8
        indicators.append("Contenu textuel incitatif")
    elif body_keyword_hits == 1:
        risk_score += 3
        indicators.append("Contenu textuel légèrement incitatif")

    # ---------------------------
    # URLs
    # ---------------------------
    for us in url_scores or []:
        score = us.get("score", 0)
        flags = us.get("flags", []) or []

        if score >= 60:
            suspicious_url_count += 1
            risk_score += 20
            for flag in flags:
                indicators.append(f"URL suspecte : {flag}")
        elif score >= 30:
            medium_url_count += 1
            risk_score += 8
            for flag in flags:
                indicators.append(f"URL atypique : {flag}")

    if suspicious_url_count >= 2:
        strong_signals.append("Plusieurs URLs suspectes")
        risk_score += 12
    elif suspicious_url_count == 1 and medium_url_count >= 1:
        risk_score += 8
        indicators.append("Combinaison d'URLs suspectes et atypiques")

    if getattr(observables, "url_count", 0) >= 6:
        risk_score += 5
        indicators.append(f"Email très riche en liens ({observables.url_count})")

    if getattr(observables, "external_domain_count", 0) >= 3:
        risk_score += 6
        indicators.append(f"Multiples domaines externes ({observables.external_domain_count})")

    # ---------------------------
    # Domain analysis
    # ---------------------------
    for dr in domain_results or []:
        domain = dr.get("domain", "inconnu")

        if dr.get("age_days") is not None and dr["age_days"] < 21:
            risk_score += 20
            strong_signals.append(f"Domaine récent : {domain}")
            indicators.append(f"Domaine récent : {domain} créé il y a {dr['age_days']} jours")
        elif dr.get("age_days") is not None and dr["age_days"] < 90:
            risk_score += 8
            indicators.append(f"Domaine assez récent : {domain} ({dr['age_days']} jours)")

        if dr.get("vt_malicious", 0) > 0:
            risk_score += 35
            strong_signals.append(f"VirusTotal positif : {domain}")
            indicators.append(
                f"VirusTotal : {domain} signalé par {dr['vt_malicious']}/{dr.get('vt_total', 0)} moteurs"
            )

        if dr.get("dns_valid") is True:
            benign_score += 1

    # ---------------------------
    # IP analysis
    # ---------------------------
    for ir in ip_results or []:
        ip = ir.get("ip", "inconnue")

        if ir.get("abuse_score", 0) >= 70:
            risk_score += 25
            strong_signals.append(f"IP à fort abuse score : {ip}")
            indicators.append(f"IP {ip} : abuse score élevé ({ir['abuse_score']}/100)")
        elif ir.get("abuse_score", 0) >= 30:
            risk_score += 8
            indicators.append(f"IP {ip} : abuse score modéré ({ir['abuse_score']}/100)")

        if ir.get("is_tor"):
            risk_score += 30
            strong_signals.append(f"IP Tor : {ip}")
            indicators.append(f"IP {ip} : nœud de sortie Tor")

    # ---------------------------
    # Redirect chains
    # ---------------------------
    for chain in redirect_chains or []:
        chain_len = len(chain)
        if chain_len > 4:
            risk_score += 8
            indicators.append(f"Chaîne de redirections longue ({chain_len} sauts)")
        elif chain_len >= 2:
            risk_score += 3
            indicators.append(f"Redirections multiples ({chain_len} sauts)")

    # ---------------------------
    # Attachments
    # ---------------------------
    dangerous_exts = [".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".ps1", ".scr", ".msi", ".hta", ".reg"]
    macro_like_exts = [".docm", ".xlsm", ".pptm", ".iso", ".img", ".lnk", ".html", ".htm", ".svg", ".zip", ".rar", ".7z"]

    if attachment_count > 0:
        indicators.append(f"Présence de {attachment_count} pièce(s) jointe(s)")
        risk_score += 3

        if suspicious_keyword_hits >= 1 or body_keyword_hits >= 1 or suspicious_url_count >= 1:
            risk_score += 5
            indicators.append("Pièce jointe combinée à un contenu déjà suspect")

    for att in attachments:
        fname = _safe_lower(getattr(att, "filename", "") or "")
        content_type = _safe_lower(getattr(att, "content_type", "") or "")

        if not fname and not content_type:
            continue

        dangerous_hit = False
        for ext in dangerous_exts:
            if fname.endswith(ext):
                risk_score += 40
                attachment_risk_hits += 1
                dangerous_hit = True
                strong_signals.append(f"Pièce jointe dangereuse : {getattr(att, 'filename', fname)}")
                indicators.append(f"Pièce jointe dangereuse : {getattr(att, 'filename', fname)}")
                break

        if dangerous_hit:
            continue

        for ext in macro_like_exts:
            if fname.endswith(ext):
                risk_score += 20
                attachment_risk_hits += 1
                indicators.append(f"Pièce jointe à risque : {getattr(att, 'filename', fname)}")
                break

        parts = fname.split(".")
        if len(parts) > 2 and parts[-2] in ("exe", "vbs", "bat", "js", "scr", "pdf", "doc", "xls"):
            risk_score += 45
            attachment_risk_hits += 1
            strong_signals.append(f"Double extension : {getattr(att, 'filename', fname)}")
            indicators.append(f"Double extension suspecte : {getattr(att, 'filename', fname)}")

    # ---------------------------
    # HTML suspicious patterns
    # ---------------------------
    suspicious_patterns = getattr(observables, "suspicious_patterns", None) or []
    if suspicious_patterns:
        pattern_count = len(suspicious_patterns)
        risk_score += min(24, 10 + pattern_count * 3)
        strong_signals.append("HTML suspect")
        indicators.append(f"{pattern_count} pattern(s) HTML suspects détectés")

    # ---------------------------
    # Reputation
    # ---------------------------
    seen_count = reputation_features.get("seen_count", 0)
    benign_ratio = reputation_features.get("benign_ratio", 0.0)
    malicious_ratio = reputation_features.get("malicious_ratio", 0.0)

    if reputation_features.get("is_established_sender"):
        benign_score += 3
        benign_signals.append("Expéditeur déjà observé")

    if reputation_features.get("is_historically_benign"):
        benign_score += 5
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

    # ---------------------------
    # Raw score clamp
    # ---------------------------
    risk_score = max(0, min(100, risk_score))
    benign_score = max(0, min(100, benign_score))

    # Les signaux bénins ne doivent pas neutraliser trop fortement le risque
    final_score = max(0, min(100, risk_score - int(benign_score * 0.20)))
    strong_count = len(set(strong_signals))

    # ---------------------------
    # Guardrails / floors
    # ---------------------------
    suspicious_combo_count = 0

    if suspicious_keyword_hits >= 1:
        suspicious_combo_count += 1
    if body_keyword_hits >= 2:
        suspicious_combo_count += 1
    if suspicious_url_count >= 1 or medium_url_count >= 2:
        suspicious_combo_count += 1
    if suspicious_patterns:
        suspicious_combo_count += 1
    if sender_identity_mismatch:
        suspicious_combo_count += 1
    if attachment_count > 0 and (suspicious_keyword_hits >= 1 or body_keyword_hits >= 1 or suspicious_url_count >= 1):
        suspicious_combo_count += 1
    if attachment_risk_hits >= 1:
        suspicious_combo_count += 1

    if strong_count >= 1 and final_score < 45:
        final_score = 45

    if suspicious_combo_count >= 2 and final_score < 35:
        final_score = 35
        indicators.append("Plancher appliqué : combinaison de signaux suspects")

    if suspicious_combo_count >= 3 and final_score < 50:
        final_score = 50
        indicators.append("Plancher appliqué : cumul significatif de signaux suspects")

    if attachment_count > 0 and final_score < 20:
        final_score = 20
        indicators.append("Plancher appliqué : présence de pièce jointe")

    if attachment_count > 0 and suspicious_combo_count >= 1 and final_score < 30:
        final_score = 30
        indicators.append("Plancher appliqué : pièce jointe + signal suspect")

    delivery_theme = any(
        kw in subject_lower or kw in body_lower
        for kw in ["delivery", "parcel", "package", "colis", "livraison", "failed delivery", "votre colis"]
    )
    if delivery_theme and final_score < 55:
        final_score = 55
        indicators.append("Plancher appliqué : thématique livraison / colis")

    # ---------------------------
    # Final level
    # ---------------------------
    if strong_count >= 2 and final_score >= 70:
        level = "CRITICAL"
        verdict = "Phishing probable — plusieurs signaux forts cumulés"
        color = "#ff4444"
    elif (strong_count >= 1 and final_score >= 55) or final_score >= 75:
        level = "HIGH"
        verdict = "Menace probable — vérification urgente requise"
        color = "#ff8800"
    elif final_score >= 30:
        level = "MEDIUM"
        verdict = "Ambigu ou atypique — analyse manuelle recommandée"
        color = "#ffcc00"
    else:
        level = "LOW"
        verdict = "Probablement sain"
        color = "#44cc44"

    if level == "LOW" and suspicious_combo_count >= 2:
        level = "MEDIUM"
        verdict = "Mail atypique avec plusieurs signaux faibles — analyse recommandée"
        color = "#ffcc00"

    if level in ("HIGH", "CRITICAL") and strong_count == 0 and final_score < 75:
        level = "MEDIUM"
        verdict = "Atypique mais sans signal fort confirmé"
        color = "#ffcc00"

    return PhishingScore(
        score=final_score,
        risk_score=risk_score,
        benign_score=benign_score,
        level=level,
        verdict=verdict,
        indicators=list(dict.fromkeys(indicators)),
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


def _safe_lower(value: str):
    return (value or "").lower()
