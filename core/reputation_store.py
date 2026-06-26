"""
PHAROS — Reputation Store
Mémoire locale de réputation par expéditeur et domaine racine.
"""

import json
import re
from pathlib import Path
from datetime import datetime, timezone


STORE_PATH = Path("data/reputation_store.json")


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


def _extract_domain(addr: str) -> str:
    m = re.search(r'@([\w.\-]+)', addr or "")
    return m.group(1).lower() if m else ""


def _root_domain(domain: str) -> str:
    parts = (domain or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "")


def _default_store():
    return {
        "version": 1,
        "updated_at": _utcnow(),
        "senders": {},
        "domains": {},
    }


def ensure_store():
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not STORE_PATH.exists():
        STORE_PATH.write_text(json.dumps(_default_store(), indent=2, ensure_ascii=False), encoding="utf-8")


def load_store():
    ensure_store()
    try:
        return json.loads(STORE_PATH.read_text(encoding="utf-8"))
    except Exception:
        data = _default_store()
        save_store(data)
        return data


def save_store(data):
    data["updated_at"] = _utcnow()
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STORE_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _new_entity():
    return {
        "seen_count": 0,
        "first_seen": None,
        "last_seen": None,
        "legit_count": 0,
        "malicious_count": 0,
        "false_positive_count": 0,
        "false_negative_count": 0,
        "last_verdict": None,
        "last_subject": None,
    }


def _touch_entity(entity, subject="", verdict=None):
    now = _utcnow()
    entity["seen_count"] += 1
    if not entity["first_seen"]:
        entity["first_seen"] = now
    entity["last_seen"] = now
    if subject:
        entity["last_subject"] = subject[:300]
    if verdict:
        entity["last_verdict"] = verdict


def record_observation(from_addr: str, subject: str = "", verdict: str = None):
    store = load_store()

    sender = (from_addr or "").strip().lower()
    domain = _extract_domain(sender)
    root = _root_domain(domain)

    if sender:
        entity = store["senders"].setdefault(sender, _new_entity())
        _touch_entity(entity, subject=subject, verdict=verdict)

    if root:
        entity = store["domains"].setdefault(root, _new_entity())
        _touch_entity(entity, subject=subject, verdict=verdict)

    save_store(store)


def apply_feedback(from_addr: str, label: str, subject: str = ""):
    """
    label in {"legit", "malicious", "false_positive", "false_negative"}
    """
    if label not in {"legit", "malicious", "false_positive", "false_negative"}:
        raise ValueError("Label de feedback invalide")

    store = load_store()

    sender = (from_addr or "").strip().lower()
    domain = _extract_domain(sender)
    root = _root_domain(domain)

    def update_entity(entity):
        _touch_entity(entity, subject=subject)
        if label == "legit":
            entity["legit_count"] += 1
        elif label == "malicious":
            entity["malicious_count"] += 1
        elif label == "false_positive":
            entity["false_positive_count"] += 1
            entity["legit_count"] += 1
        elif label == "false_negative":
            entity["false_negative_count"] += 1
            entity["malicious_count"] += 1

    if sender:
        update_entity(store["senders"].setdefault(sender, _new_entity()))

    if root:
        update_entity(store["domains"].setdefault(root, _new_entity()))

    save_store(store)


def get_reputation(from_addr: str):
    store = load_store()

    sender = (from_addr or "").strip().lower()
    domain = _extract_domain(sender)
    root = _root_domain(domain)

    sender_rep = store["senders"].get(sender, _new_entity()) if sender else _new_entity()
    domain_rep = store["domains"].get(root, _new_entity()) if root else _new_entity()

    return {
        "sender": sender,
        "domain": domain,
        "root_domain": root,
        "sender_rep": sender_rep,
        "domain_rep": domain_rep,
    }


def compute_reputation_features(from_addr: str):
    rep = get_reputation(from_addr)
    s = rep["sender_rep"]
    d = rep["domain_rep"]

    seen_count = (s.get("seen_count", 0) * 2) + d.get("seen_count", 0)
    legit_count = (s.get("legit_count", 0) * 2) + d.get("legit_count", 0)
    malicious_count = (s.get("malicious_count", 0) * 2) + d.get("malicious_count", 0)
    fp_count = (s.get("false_positive_count", 0) * 2) + d.get("false_positive_count", 0)
    fn_count = (s.get("false_negative_count", 0) * 2) + d.get("false_negative_count", 0)

    benign_ratio = legit_count / seen_count if seen_count else 0.0
    malicious_ratio = malicious_count / seen_count if seen_count else 0.0

    return {
        "root_domain": rep["root_domain"],
        "seen_count": seen_count,
        "legit_count": legit_count,
        "malicious_count": malicious_count,
        "false_positive_count": fp_count,
        "false_negative_count": fn_count,
        "benign_ratio": round(benign_ratio, 4),
        "malicious_ratio": round(malicious_ratio, 4),
        "is_established_sender": seen_count >= 3,
        "is_historically_benign": seen_count >= 3 and benign_ratio >= 0.6 and malicious_count == 0,
        "is_historically_risky": seen_count >= 2 and malicious_ratio >= 0.5,
    }
