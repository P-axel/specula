/**
 * IncidentDetailPanel — vue triage (panneau latéral)
 *
 * Répond en < 5s à : "est-ce que je dois m'en occuper ?"
 * Widget IA compact : menace + sévérité réelle + action immédiate #1.
 */
import { useEffect, useRef, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

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

const FP_COLOR = { low: "#39ff14", medium: "#ffaa00", high: "#ff2244" };

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

/* ── Widget IA compact ────────────────────────────────────────── */
function AiWidget({ incidentId }) {
  const [data,    setData]    = useState(null);   // {status, report, error, ...}
  const [starting, setStarting] = useState(false);
  const pollRef = useRef(null);
  const prevId  = useRef(null);

  const stopPoll = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };

  const fetchStatus = useCallback(async (id) => {
    try {
      const r = await fetch(`${API_BASE}/api/v1/incidents/${id}/analyse`);
      if (!r.ok) return;
      const d = await r.json();
      setData(d);
      if (d.status === "done" || d.status === "error" || d.status === "none") stopPoll();
    } catch { stopPoll(); }
  }, []);

  // Charge le statut existant à chaque changement d'incident
  useEffect(() => {
    if (!incidentId || incidentId === prevId.current) return;
    prevId.current = incidentId;
    stopPoll();
    setData(null);
    setStarting(false);
    fetchStatus(incidentId);
  }, [incidentId, fetchStatus]);

  // Si running, démarre le polling
  useEffect(() => {
    if (data?.status === "running" || data?.status === "pending") {
      if (!pollRef.current) {
        pollRef.current = setInterval(() => fetchStatus(incidentId), 3000);
      }
    }
    return () => {};
  }, [data?.status, incidentId, fetchStatus]);

  useEffect(() => stopPoll, []); // cleanup au unmount

  const analyse = useCallback(async () => {
    setStarting(true);
    try {
      const r = await fetch(`${API_BASE}/api/v1/incidents/${incidentId}/analyse`, { method: "POST" });
      const d = await r.json();
      if (r.status === 503) { setData({ status: "error", error: "Ollama non actif — lance avec l'option [3]." }); return; }
      setData(d);
      if (d.status === "running" || d.status === "pending") {
        pollRef.current = setInterval(() => fetchStatus(incidentId), 3000);
      }
    } catch { setData({ status: "error", error: "Backend inaccessible." }); }
    finally { setStarting(false); }
  }, [incidentId, fetchStatus]);

  const status    = data?.status ?? "none";
  const report    = data?.report ?? null;
  const isRunning = status === "running" || status === "pending";
  const isDone    = status === "done";
  const isError   = status === "error";

  const a = report?.analyst     ?? {};
  const r = report?.remediation ?? {};
  const c = report?.correlator  ?? {};
  const topAction = r.immediate_actions?.[0];
  const aiScore   = r.risk_score ?? null;

  return (
    <div className="triage-ai">
      <div className="triage-ai__header">
        <span className="triage-ai__label">Analyse IA</span>
        <button
          type="button"
          className={`triage-ai__btn${(isRunning || starting) ? " triage-ai__btn--loading" : ""}`}
          onClick={analyse}
          disabled={isRunning || starting}
        >
          {starting ? "Lancement…" : isRunning ? "En cours…" : isDone ? "Relancer" : "Analyser"}
        </button>
      </div>

      {isRunning && (
        <div className="triage-ai__progress">
          <span className="triage-ai__spinner" />
          Agents en cours d'analyse — résultat automatique…
        </div>
      )}

      {isError && (
        <p className="triage-ai__error">{data?.error ?? "Erreur lors de l'analyse."}</p>
      )}

      {status === "none" && !starting && (
        <p className="triage-ai__hint">IA locale — menace, sévérité réelle, remédiation.</p>
      )}

      {isDone && report && (
        <div className="triage-ai__result">
          {/* Ligne 1 : menace + sévérité réelle + score */}
          <div className="triage-ai__row">
            {a.threat_type && (
              <span className="triage-ai__chip">{a.threat_type.replace(/_/g, " ")}</span>
            )}
            {a.real_severity && (
              <span
                className="triage-ai__chip triage-ai__chip--sev"
                style={{ color: SEV_COLORS[a.real_severity] ?? "#cce4f4" }}
              >
                {a.real_severity}
              </span>
            )}
            {a.confidence !== undefined && (
              <span className="triage-ai__chip triage-ai__chip--dim">
                {Math.round(a.confidence * 100)}%
              </span>
            )}
            {aiScore !== null && (
              <span className="triage-ai__score">{aiScore}<span>/100</span></span>
            )}
          </div>

          {/* Faux positif + campagne */}
          <div className="triage-ai__row triage-ai__row--meta">
            {a.false_positive_risk && (
              <span style={{ color: FP_COLOR[a.false_positive_risk] ?? "#6899b4" }}
                    className="triage-ai__chip triage-ai__chip--dim">
                FP {a.false_positive_risk}
              </span>
            )}
            {c.is_campaign && (
              <span className="triage-ai__chip triage-ai__chip--alert">campagne</span>
            )}
            {r.escalate_to_management && (
              <span className="triage-ai__chip triage-ai__chip--alert">escalade</span>
            )}
          </div>

          {/* Action immédiate #1 */}
          {topAction && (
            <div className="triage-ai__action">
              <span className="triage-ai__action-label">Action immédiate</span>
              <span className="triage-ai__action-text">{topAction.action}</span>
              {topAction.rationale && (
                <span className="triage-ai__action-why">{topAction.rationale}</span>
              )}
            </div>
          )}

          {/* Objectif attaquant */}
          {a.attacker_objective && (
            <p className="triage-ai__objective">{a.attacker_objective}</p>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Composant principal ──────────────────────────────────────── */
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
      <div className="triage-sev-bar" />

      {/* ── Header ── */}
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

      {/* ── Statut ── */}
      <div className="triage-status-bar">
        <StatusDropdown value={currentStatus} onChange={handleStatusChange} />
      </div>

      {/* ── Métriques ── */}
      {(score !== null || conf !== null || incident.signals_count != null) && (
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
          {incident.signals_count != null && (
            <div className="triage-metric">
              <span className="triage-metric__val">{incident.signals_count}</span>
              <span className="triage-metric__lbl">signaux</span>
            </div>
          )}
        </div>
      )}

      {/* ── Flux réseau ── */}
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

      {/* ── Threat intel ── */}
      {ti?.is_known_bad && (
        <div className="triage-ti-alert">
          IoC connu — score {ti.reputation_score}/100
        </div>
      )}

      {/* ── Widget IA ── */}
      <AiWidget incidentId={incident.id} />

      {/* ── CTA investigation ── */}
      <button
        type="button"
        className="triage-investigate-btn"
        onClick={() => navigate(`/incidents/${incident.id}`, { state: { incident } })}
      >
        Rapport complet →
      </button>
    </div>
  );
}
