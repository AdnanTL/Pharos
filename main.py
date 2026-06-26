"""
PHAROS v1.0 — Serveur principal FastAPI
"""

import os
import json
import asyncio
import html
import imaplib
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

from core.eml_parser import parse_eml
from core.extractor import extract, score_url
from core.analyzers import analyze_domain, analyze_ip, follow_redirects
from core.scoring import calculate_score
from core.alerter import send_soc_alert
from core.reputation_store import (
    ensure_store,
    record_observation,
    get_reputation,
    compute_reputation_features,
    apply_feedback,
)

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH, override=True)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_imap_config() -> dict:
    return {
        "enabled": env_bool("IMAP_ENABLED", False),
        "enabled_raw": os.getenv("IMAP_ENABLED"),
        "host": os.getenv("IMAP_HOST", "").strip(),
        "port": int(os.getenv("IMAP_PORT", "993")),
        "port_raw": os.getenv("IMAP_PORT"),
        "user": os.getenv("IMAP_USER", "").strip(),
        "password": os.getenv("IMAP_PASSWORD", "").strip(),
        "folder": os.getenv("IMAP_FOLDER", "INBOX").strip() or "INBOX",
        "poll_seconds": int(os.getenv("IMAP_POLL_SECONDS", "60")),
        "mark_seen": env_bool("IMAP_MARK_SEEN", False),
    }


def is_imap_enabled() -> bool:
    imap = get_imap_config()
    return (
        imap["enabled"]
        and bool(imap["host"])
        and bool(imap["port"])
        and bool(imap["user"])
        and bool(imap["password"])
    )


CONFIG = {
    "vt_api_key": os.getenv("VT_API_KEY", ""),
    "abuseipdb_key": os.getenv("ABUSEIPDB_KEY", ""),
    "smtp_host": os.getenv("SMTP_HOST", ""),
    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    "smtp_user": os.getenv("SMTP_USER", ""),
    "smtp_pass": os.getenv("SMTP_PASS", ""),
    "soc_email": os.getenv("SOC_EMAIL", ""),
    "alert_on": os.getenv("ALERT_ON", "HIGH"),
}

app = FastAPI(title="PHAROS", version="1.0")
Path("exports").mkdir(exist_ok=True)
Path("static").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)
ensure_store()

app.mount("/static", StaticFiles(directory="static"), name="static")

ANALYSIS_STORE = {}
ANALYSIS_LIST = []


class FeedbackPayload(BaseModel):
    label: str


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = Path(__file__).parent / "templates" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/pdf-viewer", response_class=HTMLResponse)
async def pdf_viewer():
    html_path = Path(__file__).parent / "templates" / "pdf_viewer.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/api/debug/imapp")
async def api_debug_imap():
    imap = get_imap_config()
    return {
        "cwd": str(Path.cwd()),
        "base_dir": str(BASE_DIR),
        "env_path": str(ENV_PATH),
        "env_exists": ENV_PATH.exists(),
        "IMAP_ENABLED_raw": imap["enabled_raw"],
        "IMAP_ENABLED_parsed": imap["enabled"],
        "IMAP_HOST": imap["host"],
        "IMAP_PORT_raw": imap["port_raw"],
        "IMAP_PORT": imap["port"],
        "IMAP_USER": imap["user"],
        "IMAP_PASSWORD_present": bool(imap["password"]),
        "IMAP_FOLDER": imap["folder"],
        "IMAP_MARK_SEEN": imap["mark_seen"],
        "is_imap_enabled": is_imap_enabled(),
    }


@app.get("/api/status")
async def api_status():
    stats = {"total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for item in ANALYSIS_LIST:
        stats["total"] += 1
        lvl = str(item.get("risk_level", "")).lower()
        if lvl in stats:
            stats[lvl] += 1

    return {
        "app": "PHAROS",
        "version": "1.0",
        "mode": "manual_memory",
        "imap_enabled": is_imap_enabled(),
        "stats": stats,
    }


@app.post("/api/collector/run-once")
async def api_collector_run_once():
    if not is_imap_enabled():
        return {
            "ok": False,
            "message": "Collecte IMAP refusée : IMAP désactivé ou configuration incomplète.",
            "collected_count": 0,
            "debug_url": "/api/debug/imapp",
        }

    imap_cfg = get_imap_config()
    collected_count = 0
    errors = []

    try:
        mail = imaplib.IMAP4_SSL(imap_cfg["host"], imap_cfg["port"])
        mail.login(imap_cfg["user"], imap_cfg["password"])

        status, _ = mail.select(imap_cfg["folder"])
        if status != "OK":
            try:
                mail.logout()
            except Exception:
                pass
            return {
                "ok": False,
                "message": f"Impossible d'ouvrir le dossier IMAP {imap_cfg['folder']}.",
                "collected_count": 0,
            }

        status, data = mail.search(None, "UNSEEN")
        if status != "OK":
            try:
                mail.logout()
            except Exception:
                pass
            return {
                "ok": False,
                "message": "Impossible de rechercher les emails non lus.",
                "collected_count": 0,
            }

        message_ids = data[0].split()
        if not message_ids:
            try:
                mail.logout()
            except Exception:
                pass
            return {
                "ok": True,
                "message": "Aucun nouveau mail non lu.",
                "collected_count": 0,
            }

        for msg_id in message_ids:
            try:
                status, msg_data = mail.fetch(msg_id, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    errors.append(f"fetch impossible pour message {msg_id!r}")
                    continue

                raw = msg_data[0][1]
                if not raw:
                    errors.append(f"email vide pour message {msg_id!r}")
                    continue

                parsed = parse_eml(raw)
                obs = extract(parsed.body_text, parsed.body_html, parsed.from_addr)

                domain_tasks = [analyze_domain(d, CONFIG["vt_api_key"]) for d in obs.domains[:5]]
                domain_results = await asyncio.gather(*domain_tasks, return_exceptions=True)
                domain_results = [r for r in domain_results if isinstance(r, dict)]

                all_ips = list({ip for ip in obs.ips + [parsed.originating_ip] if ip})[:3]
                ip_tasks = [analyze_ip(ip, CONFIG["abuseipdb_key"]) for ip in all_ips]
                ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
                ip_results = [r for r in ip_results if isinstance(r, dict)]

                url_scores = [score_url(u) for u in obs.urls[:10]]

                redirect_tasks = [follow_redirects(u) for u in obs.urls[:3]]
                redirect_chains = await asyncio.gather(*redirect_tasks, return_exceptions=True)
                redirect_chains = [r for r in redirect_chains if isinstance(r, list)]

                reputation = get_reputation(parsed.from_addr)
                reputation_features = compute_reputation_features(parsed.from_addr)

                phishing_score = calculate_score(
                    parsed,
                    obs,
                    domain_results,
                    ip_results,
                    url_scores,
                    redirect_chains,
                    reputation_features=reputation_features,
                )

                result = {
                    "filename": f"imap_{msg_id.decode(errors='ignore')}.eml",
                    "analyzed_at": datetime.utcnow().isoformat(),
                    "email_summary": {
                        "subject": parsed.subject,
                        "from_addr": parsed.from_addr,
                        "to_addr": parsed.to_addr,
                        "reply_to": parsed.reply_to,
                        "return_path": parsed.return_path,
                        "date": parsed.date,
                        "message_id": parsed.message_id,
                        "x_mailer": parsed.x_mailer,
                        "originating_ip": parsed.originating_ip,
                        "spf": parsed.spf,
                        "dkim": parsed.dkim,
                        "dmarc": parsed.dmarc,
                    },
                    "observables": {
                        "urls": obs.urls[:20],
                        "domains": obs.domains[:10],
                        "ips": obs.ips[:10],
                        "emails": obs.emails[:10],
                        "suspicious_patterns": obs.suspicious_patterns,
                        "url_count": obs.url_count,
                        "external_domain_count": obs.external_domain_count,
                    },
                    "domain_analysis": domain_results,
                    "ip_analysis": ip_results,
                    "url_scores": [
                        {"url": obs.urls[i], **url_scores[i]}
                        for i in range(min(len(obs.urls), 10))
                    ],
                    "redirect_chains": [
                        {"original_url": obs.urls[i] if i < len(obs.urls) else "?", "chain": chain}
                        for i, chain in enumerate(redirect_chains)
                    ],
                    "attachments": [a.to_dict() for a in parsed.attachments],
                    "reputation": {
                        "root_domain": reputation.get("root_domain"),
                        "sender_rep": reputation.get("sender_rep"),
                        "domain_rep": reputation.get("domain_rep"),
                        "features": reputation_features,
                    },
                    "score": phishing_score.to_dict(),
                }

                levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                threshold = CONFIG["alert_on"].upper()
                if (
                    threshold in levels and phishing_score.level in levels and
                    levels.index(phishing_score.level) <= levels.index(threshold) and
                    CONFIG["smtp_host"]
                ):
                    result["alert"] = await send_soc_alert(CONFIG, result)
                else:
                    result["alert"] = {"sent": False, "error": "Seuil non atteint ou SMTP non configuré"}

                ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                subject_slug = (parsed.subject or "imap_mail").replace("/", "_").replace("\\", "_")
                slug = subject_slug.replace(" ", "_")[:30]
                json_path = Path("exports") / f"pharos_{slug}_{ts}.json"
                json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

                analysis_id = len(ANALYSIS_LIST) + 1
                ANALYSIS_STORE[analysis_id] = {
                    "parsed": parsed,
                    "result": result,
                }

                ANALYSIS_LIST.insert(0, {
                    "id": analysis_id,
                    "subject": parsed.subject,
                    "from_addr": parsed.from_addr,
                    "risk_level": phishing_score.level,
                    "risk_score": phishing_score.score,
                    "filename": result["filename"],
                    "analyzed_at": result["analyzed_at"],
                })

                record_observation(
                    from_addr=parsed.from_addr,
                    subject=parsed.subject,
                    verdict=phishing_score.level,
                )

                if imap_cfg["mark_seen"]:
                    mail.store(msg_id, "+FLAGS", "\\Seen")

                collected_count += 1

            except Exception as exc:
                errors.append(str(exc))

        try:
            mail.logout()
        except Exception:
            pass

        if collected_count == 0 and errors:
            return {
                "ok": False,
                "message": "Aucun mail traité.",
                "collected_count": 0,
                "errors": errors[:5],
            }

        return {
            "ok": True,
            "message": f"Collecte IMAP terminée : {collected_count} mail(s) analysé(s).",
            "collected_count": collected_count,
            "errors": errors[:5],
        }

    except Exception as exc:
        return {
            "ok": False,
            "message": f"Erreur IMAP : {str(exc)}",
            "collected_count": 0,
        }


@app.get("/api/analyses")
async def api_analyses(group: str = "safe", limit: int = 50):
    items = ANALYSIS_LIST[:]
    if group == "safe":
        items = [x for x in items if x.get("risk_level") in ("LOW", "MEDIUM")]
    elif group == "malicious":
        items = [x for x in items if x.get("risk_level") in ("HIGH", "CRITICAL", "MEDIUM")]
    return items[:limit]


@app.get("/api/analyses/{analysis_id}")
async def api_analysis_detail(analysis_id: int):
    item = ANALYSIS_STORE.get(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analyse introuvable")
    return item["result"]


@app.post("/api/analyses/{analysis_id}/feedback")
async def api_analysis_feedback(analysis_id: int, payload: FeedbackPayload):
    item = ANALYSIS_STORE.get(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analyse introuvable")

    label = (payload.label or "").strip().lower()
    if label not in {"legit", "malicious", "false_positive", "false_negative"}:
        raise HTTPException(status_code=400, detail="Label invalide")

    parsed = item["parsed"]
    apply_feedback(
        from_addr=parsed.from_addr,
        label=label,
        subject=parsed.subject,
    )

    return {
        "ok": True,
        "message": "Feedback enregistré",
        "label": label,
        "from_addr": parsed.from_addr,
    }


@app.get("/api/analyses/{analysis_id}/attachments/{sha256}/preview")
async def preview_attachment(analysis_id: int, sha256: str):
    item = ANALYSIS_STORE.get(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analyse introuvable")

    attachment = None
    for att in item["parsed"].attachments:
        if att.sha256 == sha256:
            attachment = att
            break

    if not attachment:
        raise HTTPException(status_code=404, detail="Pièce jointe introuvable")

    if attachment.preview_kind == "blocked":
        raise HTTPException(status_code=403, detail="Prévisualisation désactivée pour ce type de fichier")

    headers = {
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }

    if attachment.preview_kind == "image":
        return Response(
            content=attachment.data,
            media_type=attachment.content_type or "image/png",
            headers=headers,
        )

    if attachment.preview_kind == "text":
        safe_text = attachment.data.decode("utf-8", errors="replace")
        safe_html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Preview</title>
  <style>
    body {{
      margin: 0;
      padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: #07111f;
      color: #e8f0ff;
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.5;
    }}
  </style>
</head>
<body>{html.escape(safe_text)}</body>
</html>"""
        return HTMLResponse(content=safe_html, headers=headers)

    raise HTTPException(status_code=403, detail="Utiliser la route PDF dédiée pour ce type de fichier")


@app.get("/api/analyses/{analysis_id}/attachments/{sha256}/pdf")
async def pdf_attachment_data(analysis_id: int, sha256: str):
    item = ANALYSIS_STORE.get(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analyse introuvable")

    attachment = None
    for att in item["parsed"].attachments:
        if att.sha256 == sha256:
            attachment = att
            break

    if not attachment:
        raise HTTPException(status_code=404, detail="Pièce jointe introuvable")

    if attachment.preview_kind != "pdf":
        raise HTTPException(status_code=403, detail="Cette pièce jointe n'est pas autorisée pour PDF.js")

    headers = {
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Content-Disposition": 'inline; filename="attachment.pdf"',
    }

    return Response(
        content=attachment.data,
        media_type="application/pdf",
        headers=headers,
    )


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Seuls les fichiers .eml sont acceptés")

    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Fichier trop grand (max 10MB)")

    parsed = parse_eml(raw)
    obs = extract(parsed.body_text, parsed.body_html, parsed.from_addr)

    domain_tasks = [analyze_domain(d, CONFIG["vt_api_key"]) for d in obs.domains[:5]]
    domain_results = await asyncio.gather(*domain_tasks, return_exceptions=True)
    domain_results = [r for r in domain_results if isinstance(r, dict)]

    all_ips = list({ip for ip in obs.ips + [parsed.originating_ip] if ip})[:3]
    ip_tasks = [analyze_ip(ip, CONFIG["abuseipdb_key"]) for ip in all_ips]
    ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
    ip_results = [r for r in ip_results if isinstance(r, dict)]

    url_scores = [score_url(u) for u in obs.urls[:10]]

    redirect_tasks = [follow_redirects(u) for u in obs.urls[:3]]
    redirect_chains = await asyncio.gather(*redirect_tasks, return_exceptions=True)
    redirect_chains = [r for r in redirect_chains if isinstance(r, list)]

    reputation = get_reputation(parsed.from_addr)
    reputation_features = compute_reputation_features(parsed.from_addr)

    phishing_score = calculate_score(
        parsed, obs, domain_results, ip_results, url_scores, redirect_chains,
        reputation_features=reputation_features,
    )

    result = {
        "filename": file.filename,
        "analyzed_at": datetime.utcnow().isoformat(),
        "email_summary": {
            "subject": parsed.subject,
            "from_addr": parsed.from_addr,
            "to_addr": parsed.to_addr,
            "reply_to": parsed.reply_to,
            "return_path": parsed.return_path,
            "date": parsed.date,
            "message_id": parsed.message_id,
            "x_mailer": parsed.x_mailer,
            "originating_ip": parsed.originating_ip,
            "spf": parsed.spf,
            "dkim": parsed.dkim,
            "dmarc": parsed.dmarc,
        },
        "observables": {
            "urls": obs.urls[:20],
            "domains": obs.domains[:10],
            "ips": obs.ips[:10],
            "emails": obs.emails[:10],
            "suspicious_patterns": obs.suspicious_patterns,
            "url_count": obs.url_count,
            "external_domain_count": obs.external_domain_count,
        },
        "domain_analysis": domain_results,
        "ip_analysis": ip_results,
        "url_scores": [
            {"url": obs.urls[i], **url_scores[i]}
            for i in range(min(len(obs.urls), 10))
        ],
        "redirect_chains": [
            {"original_url": obs.urls[i] if i < len(obs.urls) else "?", "chain": chain}
            for i, chain in enumerate(redirect_chains)
        ],
        "attachments": [a.to_dict() for a in parsed.attachments],
        "reputation": {
            "root_domain": reputation.get("root_domain"),
            "sender_rep": reputation.get("sender_rep"),
            "domain_rep": reputation.get("domain_rep"),
            "features": reputation_features,
        },
        "score": phishing_score.to_dict(),
    }

    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    threshold = CONFIG["alert_on"].upper()
    if (
        threshold in levels and phishing_score.level in levels and
        levels.index(phishing_score.level) <= levels.index(threshold) and
        CONFIG["smtp_host"]
    ):
        result["alert"] = await send_soc_alert(CONFIG, result)
    else:
        result["alert"] = {"sent": False, "error": "Seuil non atteint ou SMTP non configuré"}

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    slug = file.filename.replace(".eml", "").replace(" ", "_")[:30]
    json_path = Path("exports") / f"pharos_{slug}_{ts}.json"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    analysis_id = len(ANALYSIS_LIST) + 1
    ANALYSIS_STORE[analysis_id] = {
        "parsed": parsed,
        "result": result,
    }

    ANALYSIS_LIST.insert(0, {
        "id": analysis_id,
        "subject": parsed.subject,
        "from_addr": parsed.from_addr,
        "risk_level": phishing_score.level,
        "risk_score": phishing_score.score,
        "filename": file.filename,
        "analyzed_at": result["analyzed_at"],
    })

    record_observation(
        from_addr=parsed.from_addr,
        subject=parsed.subject,
        verdict=phishing_score.level,
    )

    response_payload = dict(result)
    response_payload["analysis_id"] = analysis_id

    return JSONResponse(content=response_payload)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
