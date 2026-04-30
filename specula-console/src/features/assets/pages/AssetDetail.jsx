import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import "./AssetDetail.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

const SEV_COLORS = { critical: "#ff2244", high: "#ff6b00", medium: "#ffaa00", low: "#4fb8ff" };
const STATUS_LABELS = { open: "Ouvert", investigating: "En cours", resolved: "Résolu", false_positive: "Faux positif" };

function riskColor(s) {
  if (s >= 70) return "#ff2244";
  if (s >= 40) return "#ff6b00";
  if (s >= 10) return "#ffaa00";
  return "#39ff14";
}

function formatTs(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString("fr-FR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }); }
  catch { return ts; }
}

function AiStatusBadge({ incidentId }) {
  const [status, setStatus] = useState(null);
  const pollRef = useRef(null);

  const fetch_ = useCallback(() => {
    fetch(`${API_BASE}/api/v1/incidents/${encodeURIComponent(incidentId)}/analyse`)
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!d) return;
        setStatus(d.status);
        if (d.status === "done" || d.status === "error") {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
      }).catch(() => {});
  }, [incidentId]);

  useEffect(() => {
    fetch_();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [fetch_]);

  if (!status || status === "none") return null;
  if (status === "running" || status === "pending")
    return <span className="ad-inc__ai-badge ad-inc__ai-badge--running">IA…</span>;
  if (status === "done")
    return <span className="ad-inc__ai-badge ad-inc__ai-badge--done">IA ✓</span>;
  return null;
}

export default function AssetDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/assets/${id}/summary`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { setSummary(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [id]);

  // Lance l'IA automatiquement sur les incidents high/critical ouverts sans analyse
  useEffect(() => {
    if (!summary?.recent_incidents) return;
    const targets = summary.recent_incidents.filter(
      inc => ["critical", "high"].includes(inc.severity) &&
             ["open", "investigating"].includes(inc.status)
    );
    targets.forEach(inc => {
      fetch(`${API_BASE}/api/v1/incidents/${encodeURIComponent(inc.incident_id)}/analyse`)
        .then(r => r.ok ? r.json() : null)
        .then(d => {
          if (!d || d.status === "none") {
            fetch(`${API_BASE}/api/v1/incidents/${encodeURIComponent(inc.incident_id)}/analyse`, { method: "POST" })
              .catch(() => {});
          }
        }).catch(() => {});
    });
  }, [summary]);

  if (loading) return <div className="ad-loading">Chargement…</div>;
  if (!summary) return <div className="ad-loading">Actif introuvable.</div>;

  const asset = summary.asset || {};
  const stats = summary.stats || {};
  const score = summary.risk_score ?? 0;
  const incidents = summary.recent_incidents || [];
  const open = incidents.filter(i => ["open", "investigating"].includes(i.status));
  const closed = incidents.filter(i => !["open", "investigating"].includes(i.status));

  const name = asset.name || asset.hostname || asset.asset_id || decodeURIComponent(id);

  return (
    <div className="ad-page">
      {/* ── Header ── */}
      <div className="ad-header" style={{ "--risk-color": riskColor(score) }}>
        <div className="ad-header__bar" />
        <button className="ad-back" onClick={() => navigate("/assets")}>← Actifs</button>

        <div className="ad-header__body">
          <div className="ad-header__left">
            <div className="ad-header__eyebrow">Actif surveillé</div>
            <h1 className="ad-header__name">{name}</h1>
            <div className="ad-header__meta">
              {asset.ip_address && <span>{asset.ip_address}</span>}
              {asset.os_name && <span>{asset.os_name}</span>}
              {asset.platform && <span>{asset.platform}</span>}
              <span className={`ad-header__status${asset.status === "active" ? " ad-header__status--on" : ""}`}>
                {asset.status === "active" ? "Actif" : "Inactif"}
              </span>
            </div>
          </div>

          <div className="ad-header__right">
            <div className="ad-score" style={{ color: riskColor(score) }}>
              <span className="ad-score__val">{score}</span>
              <span className="ad-score__sub">/100</span>
            </div>
            <div className="ad-score__lbl" style={{ color: riskColor(score) }}>
              {score >= 70 ? "Critique" : score >= 40 ? "Élevé" : score >= 10 ? "Modéré" : "Sain"}
            </div>
          </div>
        </div>

        <div className="ad-stats">
          <div className="ad-stat"><span className="ad-stat__val" style={{ color: stats.open > 0 ? "#ff6b00" : undefined }}>{stats.open ?? 0}</span><span className="ad-stat__lbl">Ouverts</span></div>
          <div className="ad-stat"><span className="ad-stat__val" style={{ color: stats.critical > 0 ? "#ff2244" : undefined }}>{stats.critical ?? 0}</span><span className="ad-stat__lbl">Critiques</span></div>
          <div className="ad-stat"><span className="ad-stat__val">{stats.total ?? 0}</span><span className="ad-stat__lbl">Total</span></div>
          <div className="ad-stat"><span className="ad-stat__val">{stats.closed ?? 0}</span><span className="ad-stat__lbl">Résolus</span></div>
        </div>
      </div>

      {/* ── Incidents ouverts ── */}
      {open.length > 0 && (
        <section className="ad-section">
          <h2 className="ad-section__title">Incidents actifs</h2>
          <div className="ad-incidents">
            {open.map(inc => (
              <div
                key={inc.incident_id}
                className="ad-inc"
                style={{ "--sev-color": SEV_COLORS[inc.severity] || "#6899b4" }}
                onClick={() => navigate(`/incidents/${encodeURIComponent(inc.incident_id)}`, { state: { incident: inc } })}
              >
                <div className="ad-inc__bar" />
                <div className="ad-inc__body">
                  <div className="ad-inc__top">
                    <span className="ad-inc__sev">{inc.severity}</span>
                    <span className="ad-inc__title">{(inc.title || "Incident").replace(/\s*\(.*\)$/, "")}</span>
                    <AiStatusBadge incidentId={inc.incident_id} />
                  </div>
                  <div className="ad-inc__meta">
                    <span>{inc.dominant_engine || "—"}</span>
                    <span>{formatTs(inc.last_seen)}</span>
                    {inc.signals_count && <span>{inc.signals_count} signaux</span>}
                  </div>
                </div>
                <span className="ad-inc__arrow">→</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── Historique ── */}
      {closed.length > 0 && (
        <section className="ad-section">
          <h2 className="ad-section__title">Historique</h2>
          <div className="ad-incidents ad-incidents--closed">
            {closed.map(inc => (
              <div
                key={inc.incident_id}
                className="ad-inc ad-inc--closed"
                onClick={() => navigate(`/incidents/${encodeURIComponent(inc.incident_id)}`, { state: { incident: inc } })}
              >
                <div className="ad-inc__body">
                  <div className="ad-inc__top">
                    <span className="ad-inc__sev" style={{ color: SEV_COLORS[inc.severity] || "#6899b4" }}>{inc.severity}</span>
                    <span className="ad-inc__title">{(inc.title || "Incident").replace(/\s*\(.*\)$/, "")}</span>
                    <span className="ad-inc__status">{STATUS_LABELS[inc.status] || inc.status}</span>
                  </div>
                  <div className="ad-inc__meta"><span>{formatTs(inc.last_seen)}</span></div>
                </div>
                <span className="ad-inc__arrow">→</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {incidents.length === 0 && (
        <div className="ad-empty">Aucun incident enregistré pour cet actif.</div>
      )}
    </div>
  );
}
