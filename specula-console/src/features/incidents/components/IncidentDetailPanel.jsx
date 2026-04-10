/**
 * IncidentDetailPanel — vue triage (panneau latéral)
 *
 * Répond en < 5s à : "est-ce que je dois m'en occuper ?"
 * N'affiche PAS ce que la liste montre déjà (badges, description, signaux).
 */
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

const SEV_COLORS = {
  critical: "#ff2244",
  high:     "#ff6b00",
  medium:   "#ffaa00",
  low:      "#4fb8ff",
  info:     "#183f58",
};

const STATUS_OPTIONS = [
  { value: "open",           label: "Ouvert",       color: "#ff2244" },
  { value: "investigating",  label: "En cours",     color: "#ffaa00" },
  { value: "resolved",       label: "Résolu",       color: "#39ff14" },
  { value: "false_positive", label: "Faux positif", color: "#6899b4" },
];

function cleanTitle(title, asset) {
  if (!title) return "Incident";
  if (asset && title.endsWith(`(${asset})`)) return title.slice(0, -(asset.length + 3)).trim();
  return title;
}

function formatAge(ts) {
  if (!ts) return null;
  const ms = Date.now() - new Date(ts).getTime();
  if (ms < 0) return null;
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  if (h >= 24) return `${Math.floor(h / 24)}j`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function isUrgent(incident) {
  const sev    = String(incident.severity || "").toLowerCase();
  const status = String(incident.status || "").toLowerCase();
  const ms     = Date.now() - new Date(incident.first_seen || incident.timestamp).getTime();
  return (sev === "critical" || sev === "high") &&
    (status === "open" || status === "investigating") &&
    ms > 4 * 3_600_000;
}

function StatusDropdown({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const current = STATUS_OPTIONS.find((o) => o.value === value) ?? STATUS_OPTIONS[0];

  useEffect(() => {
    function onClickOut(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOut);
    return () => document.removeEventListener("mousedown", onClickOut);
  }, []);

  return (
    <div className="triage-status-dropdown" ref={ref}>
      <button
        type="button"
        className="triage-status-trigger"
        style={{ "--status-color": current.color }}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="triage-status-dot" />
        {current.label}
        <span className="triage-status-chevron">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="triage-status-menu">
          {STATUS_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              className={`triage-status-option${opt.value === value ? " is-active" : ""}`}
              style={{ "--status-color": opt.color }}
              onClick={() => { onChange(opt.value); setOpen(false); }}
            >
              <span className="triage-status-dot" />
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function IncidentDetailPanel({ incident, onStatusChange }) {
  const navigate = useNavigate();

  if (!incident) {
    return (
      <div className="incident-panel-empty">
        <p className="empty-state">Sélectionne un incident pour afficher son contexte enrichi.</p>
      </div>
    );
  }

  const sev        = String(incident.severity || "info").toLowerCase();
  const sevColor   = SEV_COLORS[sev] || SEV_COLORS.info;
  const title      = cleanTitle(incident.title || incident.name, incident.asset_name);
  const age        = formatAge(incident.first_seen || incident.timestamp);
  const urgent     = isUrgent(incident);
  const score      = incident.risk_score ?? null;
  const conf       = incident.confidence != null
                       ? Math.round(Number(incident.confidence) * 100)
                       : null;
  const isNetwork  = incident.kind === "network" || incident.incident_domain === "network";
  const currentStatus = incident.status ?? "open";
  const ti         = incident.threat_intel ?? null;

  const handleStatusChange = (newStatus) => {
    if (newStatus !== currentStatus) onStatusChange?.(incident.id, newStatus);
  };

  return (
    <div
      className="incident-detail-panel triage-panel"
      style={{ "--sev-color": sevColor }}
    >
      {/* Barre top sévérité via ::before CSS */}
      <div className="triage-sev-bar" />

      {/* ── Header : titre + score ── */}
      <div className="triage-header">
        <div className="triage-header__left">
          <div className="triage-header__kicker">Détail incident</div>
          <h3 className="triage-header__title">{title}</h3>
        </div>
        <div className="triage-header__right">
          {score !== null && (
            <div className="triage-score">
              <span className="triage-score__val">{score}</span>
              <span className="triage-score__sub">/100</span>
            </div>
          )}
          {age && (
            <span className={`triage-age${urgent ? " triage-age--urgent" : ""}`}>
              {urgent ? "⚠ " : ""}{age}
            </span>
          )}
        </div>
      </div>

      {/* ── Statut — dropdown ── */}
      <div className="triage-status-bar">
        <StatusDropdown value={currentStatus} onChange={handleStatusChange} />
      </div>

      {/* ── Métriques : score + confiance + détections ── */}
      {(score !== null || conf !== null || incident.detections_count != null) && (
        <div className="triage-metrics">
          {score !== null && (
            <div className="triage-metric">
              <span className="triage-metric__val">{score}</span>
              <span className="triage-metric__lbl">risque</span>
            </div>
          )}
          {conf !== null && (
            <div className="triage-metric">
              <span className="triage-metric__val">{conf}%</span>
              <span className="triage-metric__lbl">conf.</span>
            </div>
          )}
          {incident.detections_count != null && (
            <div className="triage-metric">
              <span className="triage-metric__val">{incident.detections_count}</span>
              <span className="triage-metric__lbl">signaux</span>
            </div>
          )}
        </div>
      )}

      {/* ── Flux réseau condensé ── */}
      {isNetwork && (incident.src_ip || incident.dest_ip) && (
        <div className="triage-flow">
          <code className="triage-flow__ip">{incident.src_ip || "?"}</code>
          <span className="triage-flow__arrow">→</span>
          <code className="triage-flow__ip triage-flow__ip--dest">
            {incident.dest_ip || "?"}
            {incident.dest_port ? `:${incident.dest_port}` : ""}
          </code>
          {incident.app_proto && (
            <span className="triage-flow__proto">{incident.app_proto.toUpperCase()}</span>
          )}
        </div>
      )}

      {/* ── Alerte threat intel ── */}
      {ti?.is_known_bad && (
        <div className="triage-ti-alert">
          IoC connu — score {ti.reputation_score}/100
        </div>
      )}

      {/* ── CTA investigation ── */}
      <button
        type="button"
        className="triage-investigate-btn"
        onClick={() => navigate(`/incidents/${incident.id}`, { state: { incident } })}
      >
        Ouvrir l'investigation
        <span className="triage-investigate-btn__arrow">→</span>
      </button>
    </div>
  );
}
