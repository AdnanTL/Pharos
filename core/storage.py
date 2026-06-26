"""
PHAROS — Storage layer SQLite
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path


def get_conn(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = get_conn(db_path)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyzed_at TEXT NOT NULL,
            received_at TEXT NOT NULL DEFAULT '',
            filename TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_ref TEXT NOT NULL DEFAULT '',
            risk_score INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'LOW',
            subject TEXT NOT NULL DEFAULT '',
            from_addr TEXT NOT NULL DEFAULT '',
            verdict TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL
        )
    """)

    conn.commit()

    cols = {
        row["name"]: row
        for row in conn.execute("PRAGMA table_info(analyses)").fetchall()
    }

    if "received_at" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN received_at TEXT NOT NULL DEFAULT ''")
    if "source_type" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN source_type TEXT NOT NULL DEFAULT 'manual'")
    if "source_ref" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN source_ref TEXT NOT NULL DEFAULT ''")
    if "risk_score" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
    if "risk_level" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'LOW'")
    if "subject" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN subject TEXT NOT NULL DEFAULT ''")
    if "from_addr" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN from_addr TEXT NOT NULL DEFAULT ''")
    if "verdict" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN verdict TEXT NOT NULL DEFAULT ''")
    if "raw_json" not in cols:
        conn.execute("ALTER TABLE analyses ADD COLUMN raw_json TEXT NOT NULL DEFAULT '{}'")

    conn.commit()
    conn.close()


def save_analysis(result: dict, db_path: str):
    conn = get_conn(db_path)

    score = result.get("score", {}) or {}
    email_summary = result.get("email_summary", {}) or {}

    source_type = result.get("source_type") or "manual"
    source_ref = result.get("source_ref") or result.get("filename") or ""
    received_at = result.get("received_at") or result.get("analyzed_at") or datetime.utcnow().isoformat()

    conn.execute("""
        INSERT INTO analyses (
            analyzed_at,
            received_at,
            filename,
            source_type,
            source_ref,
            risk_score,
            risk_level,
            subject,
            from_addr,
            verdict,
            raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result.get("analyzed_at", datetime.utcnow().isoformat()),
        received_at,
        result.get("filename", "email.eml"),
        source_type,
        source_ref,
        int(score.get("score", 0)),
        score.get("level", "LOW"),
        email_summary.get("subject", ""),
        email_summary.get("from_addr", ""),
        score.get("verdict", ""),
        json.dumps(result, ensure_ascii=False),
    ))

    conn.commit()
    conn.close()


def list_analyses(db_path: str, group: str = "safe", limit: int = 50):
    conn = get_conn(db_path)

    if group == "malicious":
        query = """
            SELECT id, analyzed_at, received_at, filename, source_type, source_ref,
                   risk_score, risk_level, subject, from_addr, verdict
            FROM analyses
            WHERE date(analyzed_at) = date('now')
              AND risk_level IN ('MEDIUM', 'HIGH', 'CRITICAL')
            ORDER BY received_at DESC, analyzed_at DESC, id DESC
            LIMIT ?
        """
    else:
        query = """
            SELECT id, analyzed_at, received_at, filename, source_type, source_ref,
                   risk_score, risk_level, subject, from_addr, verdict
            FROM analyses
            WHERE date(analyzed_at) = date('now')
              AND risk_level IN ('LOW')
            ORDER BY received_at DESC, analyzed_at DESC, id DESC
            LIMIT ?
        """

    rows = conn.execute(query, (limit,)).fetchall()
    conn.close()

    return [
        {
            "id": row["id"],
            "analyzed_at": row["analyzed_at"],
            "received_at": row["received_at"],
            "filename": row["filename"],
            "source_type": row["source_type"],
            "source_ref": row["source_ref"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "subject": row["subject"],
            "from_addr": row["from_addr"],
            "verdict": row["verdict"],
        }
        for row in rows
    ]


def get_analysis_by_id(db_path: str, analysis_id: int):
    conn = get_conn(db_path)
    row = conn.execute(
        "SELECT raw_json FROM analyses WHERE id = ?",
        (analysis_id,)
    ).fetchone()
    conn.close()

    if not row:
        return None

    try:
        return json.loads(row["raw_json"])
    except Exception:
        return None


def get_today_stats(db_path: str):
    conn = get_conn(db_path)

    total = conn.execute("""
        SELECT COUNT(*) AS c
        FROM analyses
        WHERE date(analyzed_at) = date('now')
    """).fetchone()["c"]

    low = conn.execute("""
        SELECT COUNT(*) AS c
        FROM analyses
        WHERE date(analyzed_at) = date('now')
          AND risk_level = 'LOW'
    """).fetchone()["c"]

    medium = conn.execute("""
        SELECT COUNT(*) AS c
        FROM analyses
        WHERE date(analyzed_at) = date('now')
          AND risk_level = 'MEDIUM'
    """).fetchone()["c"]

    high = conn.execute("""
        SELECT COUNT(*) AS c
        FROM analyses
        WHERE date(analyzed_at) = date('now')
          AND risk_level = 'HIGH'
    """).fetchone()["c"]

    critical = conn.execute("""
        SELECT COUNT(*) AS c
        FROM analyses
        WHERE date(analyzed_at) = date('now')
          AND risk_level = 'CRITICAL'
    """).fetchone()["c"]

    conn.close()

    return {
        "total": total,
        "low": low,
        "medium": medium,
        "high": high,
        "critical": critical,
    }


def get_last_imap_uid(db_path: str) -> int:
    conn = get_conn(db_path)
    row = conn.execute("""
        SELECT source_ref
        FROM analyses
        WHERE source_type = 'imap'
          AND source_ref GLOB '[0-9]*'
        ORDER BY CAST(source_ref AS INTEGER) DESC
        LIMIT 1
    """).fetchone()
    conn.close()

    if not row or not row["source_ref"]:
        return 0

    try:
        return int(row["source_ref"])
    except Exception:
        return 0
