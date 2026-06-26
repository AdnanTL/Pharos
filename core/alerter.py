"""
PHAROS — SOC Alerter
Envoie un email d'alerte quand un phishing est détecté
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


async def send_soc_alert(config: dict, scan_result: dict) -> dict:
    """Envoie l'alerte. Retourne {"sent": True/False, "error": "..."}"""

    smtp_host = config.get("smtp_host", "")
    smtp_port = config.get("smtp_port", 587)
    smtp_user = config.get("smtp_user", "")
    smtp_pass = config.get("smtp_pass", "")
    soc_email = config.get("soc_email", "")

    if not all([smtp_host, smtp_user, smtp_pass, soc_email]):
        return {"sent": False, "error": "SMTP non configuré dans .env"}

    score      = scan_result.get("score", {})
    email_info = scan_result.get("email_summary", {})
    level      = score.get("level", "UNKNOWN")
    indicators = score.get("indicators", [])

    colors = {
        "CRITICAL": "#ff4444", "HIGH": "#ff8800",
        "MEDIUM": "#ffcc00",   "LOW": "#44cc44",
    }
    color = colors.get(level, "#aaa")

    indicators_html = "".join(
        f"<li style='margin:4px 0'>⚠️ {ind}</li>"
        for ind in indicators[:15]
    )

    html_body = f"""
    <html><body style="font-family:Arial;background:#0d1117;color:#c9d1d9;padding:20px">
    <div style="max-width:600px;margin:auto">
      <h2 style="color:#58a6ff">⚡ PHAROS — Alerte Phishing</h2>

      <div style="background:#161b22;border:2px solid {color};border-radius:8px;padding:16px;margin:16px 0">
        <h3 style="color:{color};margin:0">Niveau de risque : {level} ({score.get('score',0)}/100)</h3>
        <p style="color:#8b949e">{score.get('verdict','')}</p>
      </div>

      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:16px 0">
        <h4 style="color:#58a6ff">Détails de l'email</h4>
        <table style="font-size:.9em;width:100%">
          <tr><td style="color:#8b949e;width:100px">De</td><td>{email_info.get('from_addr','')}</td></tr>
          <tr><td style="color:#8b949e">À</td><td>{email_info.get('to_addr','')}</td></tr>
          <tr><td style="color:#8b949e">Sujet</td><td>{email_info.get('subject','')}</td></tr>
          <tr><td style="color:#8b949e">Date</td><td>{email_info.get('date','')}</td></tr>
          <tr><td style="color:#8b949e">SPF</td><td>{email_info.get('spf','')}</td></tr>
          <tr><td style="color:#8b949e">DKIM</td><td>{email_info.get('dkim','')}</td></tr>
        </table>
      </div>

      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:16px 0">
        <h4 style="color:#58a6ff">Indicateurs ({len(indicators)})</h4>
        <ul style="margin:0;padding-left:16px">{indicators_html}</ul>
      </div>

      <p style="color:#8b949e;font-size:.8em">
        Détecté le {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC par PHAROS v1.0
      </p>
    </div></body></html>
    """

    msg            = MIMEMultipart("alternative")
    msg["Subject"] = f"[PHAROS] {level} — Phishing détecté : {email_info.get('subject','')[:50]}"
    msg["From"]    = smtp_user
    msg["To"]      = soc_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, soc_email, msg.as_string())
        return {"sent": True, "error": ""}
    except Exception as e:
        return {"sent": False, "error": str(e)}

