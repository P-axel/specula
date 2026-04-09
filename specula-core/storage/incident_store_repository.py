"""
Repository CRUD pour les annotations d'incidents.
Toutes les requêtes utilisent des paramètres liés (pas de concaténation) pour prévenir l'injection SQL.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from storage.database import get_connection

MAX_NOTE_LENGTH = 10_000
MAX_ATTACHMENT_SIZE = 2 * 1024 * 1024  # 2 Mo en octets


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Statuts ───────────────────────────────────────────────────────────────────

def get_all_statuses() -> dict[str, str]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT incident_id, status FROM incident_statuses"
        ).fetchall()
    return {row["incident_id"]: row["status"] for row in rows}


def get_status(incident_id: str) -> str | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT status FROM incident_statuses WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
    return row["status"] if row else None


def set_status(incident_id: str, status: str, from_status: str | None = None) -> None:
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO incident_statuses (incident_id, status, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at
            """,
            (incident_id, status, now),
        )
        conn.execute(
            "INSERT INTO incident_status_history (incident_id, from_status, to_status, ts) VALUES (?, ?, ?, ?)",
            (incident_id, from_status, status, now),
        )


# ── Historique de statut ───────────────────────────────────────────────────────

def get_status_history(incident_id: str) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT from_status, to_status, ts FROM incident_status_history WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]


# ── Notes ─────────────────────────────────────────────────────────────────────

def get_notes(incident_id: str) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, text, ts FROM incident_notes WHERE incident_id = ? ORDER BY ts ASC",
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def add_note(incident_id: str, text: str) -> dict[str, Any]:
    if not text or not text.strip():
        raise ValueError("Le texte de la note ne peut pas être vide.")
    if len(text) > MAX_NOTE_LENGTH:
        raise ValueError(f"Note trop longue (max {MAX_NOTE_LENGTH} caractères).")

    note_id = str(uuid.uuid4())
    now = _now()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO incident_notes (id, incident_id, text, ts) VALUES (?, ?, ?, ?)",
            (note_id, incident_id, text.strip(), now),
        )
    return {"id": note_id, "text": text.strip(), "ts": now}


def delete_note(incident_id: str, note_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM incident_notes WHERE id = ? AND incident_id = ?",
            (note_id, incident_id),
        )
    return cursor.rowcount > 0


# ── Pièces jointes ────────────────────────────────────────────────────────────

def get_attachments(incident_id: str) -> list[dict[str, Any]]:
    """Retourne les métadonnées sans le contenu binaire."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, name, size, mime_type, ts FROM incident_attachments WHERE incident_id = ? ORDER BY ts ASC",
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_attachment_data(incident_id: str, attachment_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, name, size, mime_type, data, ts FROM incident_attachments WHERE id = ? AND incident_id = ?",
            (attachment_id, incident_id),
        ).fetchone()
    return dict(row) if row else None


def add_attachment(
    incident_id: str,
    name: str,
    size: int,
    mime_type: str | None,
    data: str,  # base64
) -> dict[str, Any]:
    # Validation côté serveur
    name = name.strip()
    if not name:
        raise ValueError("Nom de fichier invalide.")
    # Empêcher path traversal
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("Nom de fichier non autorisé.")
    if size > MAX_ATTACHMENT_SIZE:
        raise ValueError(f"Fichier trop volumineux (max 2 Mo).")

    att_id = str(uuid.uuid4())
    now = _now()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO incident_attachments (id, incident_id, name, size, mime_type, data, ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (att_id, incident_id, name, size, mime_type, data, now),
        )
    return {"id": att_id, "name": name, "size": size, "mime_type": mime_type, "ts": now}


def delete_attachment(incident_id: str, attachment_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM incident_attachments WHERE id = ? AND incident_id = ?",
            (attachment_id, incident_id),
        )
    return cursor.rowcount > 0


# ── Chargement complet d'un incident ─────────────────────────────────────────

def get_incident_store(incident_id: str) -> dict[str, Any]:
    return {
        "status": get_status(incident_id),
        "statusHistory": get_status_history(incident_id),
        "notes": get_notes(incident_id),
        "attachments": get_attachments(incident_id),
    }


# ── Cycle de vie des incidents (table incidents) ──────────────────────────────

def get_incident_lifecycle(signature: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE signature = ?",
            (signature,),
        ).fetchone()
    return dict(row) if row else None


def upsert_incident_lifecycle(
    signature: str,
    incident_id: str,
    title: str | None,
    asset_name: str | None,
    dominant_engine: str | None,
    incident_domain: str | None,
    severity: str | None,
    risk_score: int | None,
    status: str,
    signals_count: int,
    first_seen: str | None,
    last_seen: str | None,
) -> None:
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO incidents
                (signature, incident_id, title, asset_name, dominant_engine, incident_domain,
                 severity, risk_score, status, signals_count, first_seen, last_seen,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(signature) DO UPDATE SET
                incident_id     = excluded.incident_id,
                title           = excluded.title,
                asset_name      = excluded.asset_name,
                dominant_engine = excluded.dominant_engine,
                incident_domain = excluded.incident_domain,
                severity        = excluded.severity,
                risk_score      = MAX(incidents.risk_score, excluded.risk_score),
                signals_count   = excluded.signals_count,
                last_seen       = excluded.last_seen,
                updated_at      = excluded.updated_at
            """,
            (
                signature, incident_id, title, asset_name, dominant_engine, incident_domain,
                severity, risk_score, status, signals_count, first_seen, last_seen,
                now, now,
            ),
        )


def update_incident_status_by_signature(signature: str, status: str) -> bool:
    now = _now()
    resolved_at = now if status in ("resolved", "false_positive") else None
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE incidents
            SET status = ?, resolved_at = COALESCE(?, resolved_at), updated_at = ?
            WHERE signature = ?
            """,
            (status, resolved_at, now, signature),
        )
    return cursor.rowcount > 0


def get_incident_id_by_signature(signature: str) -> str | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT incident_id FROM incidents WHERE signature = ?",
            (signature,),
        ).fetchone()
    return row["incident_id"] if row else None
