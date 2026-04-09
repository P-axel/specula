import { useState, useEffect, useCallback } from "react";

const API = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

// ── Helpers API ───────────────────────────────────────────────────────────────

async function apiFetch(path, options = {}) {
  try {
    const res = await fetch(`${API}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (res.status === 204) return null;
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// ── Statuts globaux — appelés depuis Incidents.jsx ────────────────────────────

export async function loadLocalStatuses() {
  const data = await apiFetch("/incidents/statuses");
  return data ?? {};
}

export async function saveLocalStatus(id, status) {
  await apiFetch(`/incidents/${id}/status`, {
    method: "PUT",
    body: JSON.stringify({ status }),
  });
}

export async function saveStatusTransition(incidentId, from, to) {
  await apiFetch(`/incidents/${incidentId}/status`, {
    method: "PUT",
    body: JSON.stringify({ status: to, from_status: from }),
  });
}

// ── Hook notes / pièces jointes / historique par incident ─────────────────────

export function useIncidentStore(incidentId) {
  const [comments, setComments] = useState([]);
  const [attachments, setAttachments] = useState([]);
  const [statusHistory, setStatusHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  // Chargement initial depuis l'API
  useEffect(() => {
    if (!incidentId) return;
    setLoading(true);
    apiFetch(`/incidents/${incidentId}/store`).then((data) => {
      if (data) {
        setComments(data.notes ?? []);
        setAttachments(data.attachments ?? []);
        setStatusHistory(data.statusHistory ?? []);
      }
      setLoading(false);
    });
  }, [incidentId]);

  // ── Notes ──────────────────────────────────────────────────────────────────

  const addComment = useCallback(async (text) => {
    const trimmed = text?.trim();
    if (!trimmed) return;
    const note = await apiFetch(`/incidents/${incidentId}/notes`, {
      method: "POST",
      body: JSON.stringify({ text: trimmed }),
    });
    if (note) setComments((prev) => [...prev, note]);
  }, [incidentId]);

  const deleteComment = useCallback(async (commentId) => {
    const ok = await apiFetch(`/incidents/${incidentId}/notes/${commentId}`, {
      method: "DELETE",
    });
    if (ok !== undefined) {
      setComments((prev) => prev.filter((c) => c.id !== commentId));
    }
  }, [incidentId]);

  // ── Pièces jointes ─────────────────────────────────────────────────────────

  const addAttachment = useCallback((file) => {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      alert("Fichier trop volumineux (max 2 Mo)");
      return;
    }
    const reader = new FileReader();
    reader.onload = async (e) => {
      const att = await apiFetch(`/incidents/${incidentId}/attachments`, {
        method: "POST",
        body: JSON.stringify({
          name: file.name,
          size: file.size,
          mime_type: file.type || null,
          data: e.target.result, // base64 data URL
        }),
      });
      if (att) setAttachments((prev) => [...prev, att]);
    };
    reader.readAsDataURL(file);
  }, [incidentId]);

  const deleteAttachment = useCallback(async (attachmentId) => {
    await apiFetch(`/incidents/${incidentId}/attachments/${attachmentId}`, {
      method: "DELETE",
    });
    setAttachments((prev) => prev.filter((a) => a.id !== attachmentId));
  }, [incidentId]);

  const downloadAttachment = useCallback(async (attachment) => {
    const data = await apiFetch(
      `/incidents/${incidentId}/attachments/${attachment.id}`
    );
    if (!data?.data) return;
    const a = document.createElement("a");
    a.href = data.data;
    a.download = attachment.name;
    a.click();
  }, [incidentId]);

  return {
    comments,
    attachments,
    statusHistory,
    loading,
    addComment,
    deleteComment,
    addAttachment,
    deleteAttachment,
    downloadAttachment,
  };
}
