import json
from typing import Any

from storage.database import get_connection


def get(incident_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM ai_analyses WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
    if not row:
        return None
    data = dict(row)
    if data.get("report_json"):
        try:
            data["report"] = json.loads(data["report_json"])
        except Exception:
            pass
    data.pop("report_json", None)
    return data


def set_pending(incident_id: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO ai_analyses (incident_id, status)
               VALUES (?, 'pending')
               ON CONFLICT(incident_id) DO UPDATE SET status='pending', error=NULL, report_json=NULL""",
            (incident_id,),
        )


def set_running(incident_id: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO ai_analyses (incident_id, status)
               VALUES (?, 'running')
               ON CONFLICT(incident_id) DO UPDATE SET status='running', error=NULL, report_json=NULL""",
            (incident_id,),
        )


def reset_stuck() -> int:
    """Remet en 'error' les analyses bloquées en pending/running au démarrage."""
    with get_connection() as conn:
        cur = conn.execute(
            """UPDATE ai_analyses SET status='error', error='Interrompu (redémarrage serveur)'
               WHERE status IN ('pending','running')"""
        )
        return cur.rowcount


def save(report: dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO ai_analyses (incident_id, status, analysed_at, model, duration_s, report_json)
               VALUES (?, 'done', ?, ?, ?, ?)
               ON CONFLICT(incident_id) DO UPDATE SET
                 status      = 'done',
                 analysed_at = excluded.analysed_at,
                 model       = excluded.model,
                 duration_s  = excluded.duration_s,
                 error       = NULL,
                 report_json = excluded.report_json""",
            (
                report["incident_id"],
                report["analysed_at"],
                report["model"],
                report.get("duration_s"),
                json.dumps(report),
            ),
        )


def set_error(incident_id: str, message: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO ai_analyses (incident_id, status, error)
               VALUES (?, 'error', ?)
               ON CONFLICT(incident_id) DO UPDATE SET status='error', error=excluded.error""",
            (incident_id, message),
        )
