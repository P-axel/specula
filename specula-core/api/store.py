"""
Routes FastAPI pour les annotations d'incidents (statuts, notes, pièces jointes).
Toutes les données sont persistées dans SQLite via incident_store_repository.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

import storage.incident_store_repository as repo
from api.auth import require_auth

router = APIRouter(
    prefix="/incidents",
    tags=["store"],
    dependencies=[Depends(require_auth)],
)


# ── Schémas ───────────────────────────────────────────────────────────────────

class StatusUpdate(BaseModel):
    status: str = Field(..., pattern=r"^(open|investigating|resolved|false_positive)$")
    from_status: str | None = None


class NoteCreate(BaseModel):
    text: str = Field(..., min_length=1, max_length=10_000)


class AttachmentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    size: int = Field(..., gt=0, le=2 * 1024 * 1024)
    mime_type: str | None = None
    data: str = Field(..., min_length=1)  # base64


# ── Statuts globaux (chargement initial de la console) ────────────────────────

@router.get("/statuses")
def get_all_statuses() -> dict[str, str]:
    """Retourne un dict {incident_id: status} pour tous les incidents annotés."""
    return repo.get_all_statuses()


# ── Store complet d'un incident ───────────────────────────────────────────────

@router.get("/{incident_id}/store")
def get_store(incident_id: str) -> dict:
    return repo.get_incident_store(incident_id)


# ── Statut ────────────────────────────────────────────────────────────────────

@router.put("/{incident_id}/status", status_code=status.HTTP_200_OK)
def update_status(incident_id: str, body: StatusUpdate) -> dict:
    # Persister dans incident_statuses (lookup frontend par ID)
    repo.set_status(incident_id, body.status, body.from_status)
    # Propager dans la table incidents (cycle de vie par signature)
    try:
        from storage.database import get_connection
        with get_connection() as conn:
            row = conn.execute(
                "SELECT signature FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        if row:
            repo.update_incident_status_by_signature(row["signature"], body.status)
    except Exception:
        pass
    return {"incident_id": incident_id, "status": body.status}


# ── Notes ─────────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/notes")
def list_notes(incident_id: str) -> list:
    return repo.get_notes(incident_id)


@router.post("/{incident_id}/notes", status_code=status.HTTP_201_CREATED)
def create_note(incident_id: str, body: NoteCreate) -> dict:
    try:
        return repo.add_note(incident_id, body.text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/{incident_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(incident_id: str, note_id: str) -> None:
    if not repo.delete_note(incident_id, note_id):
        raise HTTPException(status_code=404, detail="Note introuvable.")


# ── Pièces jointes ────────────────────────────────────────────────────────────

@router.get("/{incident_id}/attachments")
def list_attachments(incident_id: str) -> list:
    return repo.get_attachments(incident_id)


@router.post("/{incident_id}/attachments", status_code=status.HTTP_201_CREATED)
def create_attachment(incident_id: str, body: AttachmentCreate) -> dict:
    try:
        return repo.add_attachment(
            incident_id,
            name=body.name,
            size=body.size,
            mime_type=body.mime_type,
            data=body.data,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/{incident_id}/attachments/{attachment_id}")
def download_attachment(incident_id: str, attachment_id: str) -> dict:
    att = repo.get_attachment_data(incident_id, attachment_id)
    if not att:
        raise HTTPException(status_code=404, detail="Pièce jointe introuvable.")
    return att


@router.delete("/{incident_id}/attachments/{attachment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_attachment(incident_id: str, attachment_id: str) -> None:
    if not repo.delete_attachment(incident_id, attachment_id):
        raise HTTPException(status_code=404, detail="Pièce jointe introuvable.")
