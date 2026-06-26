"""
PHAROS — IMAP Collector
Collecte uniquement les emails reçus aujourd'hui
"""

import imaplib
from datetime import datetime, timezone
from email import message_from_bytes
from email.utils import parsedate_to_datetime

from core.storage import was_processed, mark_processed


def _today_local_date():
    return datetime.now().date()


def _mail_date_is_today(msg) -> bool:
    raw_date = msg.get("Date", "")
    if not raw_date:
        return False
    try:
        dt = parsedate_to_datetime(raw_date)
        if dt is None:
            return False
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().date() == _today_local_date()
    except Exception:
        return False


def collect_imap_once(config: dict) -> list:
    results = []

    if not config.get("imap_enabled"):
        print("[IMAP] IMAP désactivé dans la configuration")
        return results

    host = config.get("imap_host", "")
    port = int(config.get("imap_port", 993))
    user = config.get("imap_user", "")
    password = config.get("imap_pass", "")
    folder = config.get("imap_folder", "INBOX")
    mark_seen = config.get("imap_mark_seen", False)

    if not all([host, user, password]):
        print("[IMAP] Configuration IMAP incomplète")
        return results

    mail = None

    try:
        print(f"[IMAP] Connexion à {host}:{port} avec {user}")
        mail = imaplib.IMAP4_SSL(host, port)
        mail.login(user, password)
        mail.select(folder)

        status, data = mail.search(None, "UNSEEN")
        if status != "OK":
            print(f"[IMAP] Erreur search(): {status}")
            return results

        if not data or not data[0]:
            print("[IMAP] Aucun mail non lu trouvé")
            return results

        message_nums = data[0].split()
        print(f"[IMAP] {len(message_nums)} mail(s) non lu(s) trouvé(s), filtrage sur la date du jour...")

        for num in message_nums:
            try:
                status, msg_data = mail.fetch(num, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue

                raw_email = msg_data[0][1]
                msg = message_from_bytes(raw_email)

                if not _mail_date_is_today(msg):
                    continue

                message_id = (msg.get("Message-ID") or "").strip()
                if message_id and was_processed(message_id):
                    print(f"[IMAP] Déjà traité: {message_id}")
                    continue

                item = {
                    "message_num": num.decode() if isinstance(num, bytes) else str(num),
                    "message_id": message_id,
                    "raw_email": raw_email,
                    "subject": msg.get("Subject", ""),
                    "from_addr": msg.get("From", ""),
                    "date": msg.get("Date", ""),
                }
                results.append(item)

                if message_id:
                    mark_processed(message_id)

                if mark_seen:
                    mail.store(num, "+FLAGS", "\\Seen")

            except Exception as e:
                print(f"[IMAP] Erreur sur un message: {e}")

        print(f"[IMAP] {len(results)} mail(s) retenu(s) après filtrage sur aujourd'hui")

    except Exception as e:
        print(f"[IMAP] Erreur de connexion IMAP: {e}")

    finally:
        try:
            if mail is not None:
                mail.close()
                mail.logout()
        except Exception:
            pass

    return results
