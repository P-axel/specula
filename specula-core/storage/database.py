"""
SQLite database — initialisation et connexion.
Stocke les annotations des incidents (statuts, notes, pièces jointes, historique).
Le fichier est persisté dans runtime/db/specula.db (monté via docker-compose).
"""

import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.getenv("SPECULA_DB_PATH", "/app/runtime/db/specula.db"))


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS incident_statuses (
                incident_id TEXT PRIMARY KEY,
                status      TEXT NOT NULL DEFAULT 'open',
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incident_status_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                from_status TEXT,
                to_status   TEXT NOT NULL,
                ts          TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incident_notes (
                id          TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                text        TEXT NOT NULL,
                ts          TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incident_attachments (
                id          TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                name        TEXT NOT NULL,
                size        INTEGER NOT NULL,
                mime_type   TEXT,
                data        TEXT NOT NULL,
                ts          TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                signature       TEXT PRIMARY KEY,
                incident_id     TEXT NOT NULL,
                title           TEXT,
                asset_name      TEXT,
                dominant_engine TEXT,
                incident_domain TEXT,
                severity        TEXT,
                risk_score      INTEGER,
                status          TEXT NOT NULL DEFAULT 'open',
                signals_count   INTEGER NOT NULL DEFAULT 1,
                first_seen      TEXT,
                last_seen       TEXT,
                resolved_at     TEXT,
                raw_json        TEXT,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_status
                ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_engine
                ON incidents(dominant_engine);
            CREATE INDEX IF NOT EXISTS idx_notes_incident
                ON incident_notes(incident_id);
            CREATE INDEX IF NOT EXISTS idx_attachments_incident
                ON incident_attachments(incident_id);
            CREATE INDEX IF NOT EXISTS idx_history_incident
                ON incident_status_history(incident_id);

            CREATE TABLE IF NOT EXISTS ai_analyses (
                incident_id  TEXT PRIMARY KEY,
                status       TEXT NOT NULL DEFAULT 'pending',
                analysed_at  TEXT,
                model        TEXT,
                duration_s   REAL,
                error        TEXT,
                report_json  TEXT
            );
        """)
        # Migration v2 — rendre analysed_at nullable + ajouter status/error
        cols = [r[1] for r in conn.execute("PRAGMA table_info(ai_analyses)").fetchall()]
        if "status" not in cols or (
            "analysed_at" in cols and
            any(r[1] == "analysed_at" and r[3] == 1  # notnull flag
                for r in conn.execute("PRAGMA table_info(ai_analyses)").fetchall())
        ):
            rows = conn.execute("SELECT * FROM ai_analyses").fetchall()
            conn.executescript("""
                DROP TABLE IF EXISTS ai_analyses_old;
                ALTER TABLE ai_analyses RENAME TO ai_analyses_old;
                CREATE TABLE ai_analyses (
                    incident_id  TEXT PRIMARY KEY,
                    status       TEXT NOT NULL DEFAULT 'pending',
                    analysed_at  TEXT,
                    model        TEXT,
                    duration_s   REAL,
                    error        TEXT,
                    report_json  TEXT
                );
            """)
            for r in rows:
                d = dict(r)
                conn.execute(
                    "INSERT OR IGNORE INTO ai_analyses VALUES (?,?,?,?,?,?,?)",
                    (d["incident_id"], d.get("status", "done"), d.get("analysed_at"),
                     d.get("model"), d.get("duration_s"), d.get("error"), d.get("report_json")),
                )
            conn.execute("DROP TABLE IF EXISTS ai_analyses_old")
            conn.commit()
