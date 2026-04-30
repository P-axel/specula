import React from "react";
import { formatDateTime, formatRelativeAge } from "../lib/incidentFormatters";
import {
  PriorityBadge,
  IncidentKindBadge,
  IncidentEngineBadge,
} from "./IncidentBadges";

const STATUS_OPTIONS = [
  { value: "open", label: "Ouvert", color: "#ff2244" },
  { value: "investigating", label: "En cours", color: "#ffaa00" },
  { value: "resolved", label: "Résolu", color: "#39ff14" },
  { value: "false_positive", label: "Faux positif", color: "#7a7a9a" },
];

const SEV_BAR_COLORS = {
  critical: "#ff2244",
  high: "#ff6b00",
  medium: "#ffaa00",
  low: "#4fb8ff",
  info: "#355d78",
};

export default function IncidentListItem({
  incident,
  isSelected,
  onSelect,
  onStatusChange,
}) {
  const count = incident.signals_count ?? incident.detections_count ?? 0;
  const hasCves = Array.isArray(incident.cves) && incident.cves.length > 0;
  const ts = incident.first_seen || incident.timestamp;
  const age = formatRelativeAge(ts);

  // Âge urgent : > 4h pour critical/high toujours ouvert
  const sev = String(incident.severity || incident.priority || "").toLowerCase();
  const ageMs = ts ? Date.now() - new Date(ts).getTime() : 0;
  const isUrgentAge = (sev === "critical" || sev === "high") &&
    (incident.status === "open" || incident.status === "investigating") &&
    ageMs > 4 * 60 * 60 * 1000;

  const sevBarColor = SEV_BAR_COLORS[sev] || SEV_BAR_COLORS.info;

  const idx = STATUS_OPTIONS.findIndex((o) => o.value === incident.status);
  const current = idx >= 0 ? STATUS_OPTIONS[idx] : STATUS_OPTIONS[0];
  const next = STATUS_OPTIONS[(idx + 1) % STATUS_OPTIONS.length];
  const isOpen = current.value === "open";

  const handleStatusClick = (e) => {
    e.stopPropagation();
    onStatusChange?.(incident.id, next.value);
  };

  const handleTakeOver = (e) => {
    e.stopPropagation();
    onStatusChange?.(incident.id, "investigating");
  };

  return (
    <button
      type="button"
      className={`incident-list-item ${isSelected ? "is-selected" : ""} ${current.value === "false_positive" ? "is-fp" : ""}`}
      style={{ "--sev-bar-color": sevBarColor }}
      onClick={() => onSelect(incident)}
    >
      <div className="incident-list-item__top">
        <div className="incident-list-item__heading">
          <div className="incident-list-item__title">{incident.title || "-"}</div>
          <div className="incident-list-item__subtitle">
            {incident.asset_name || "Actif non identifié"}
          </div>
        </div>

        <div className="incident-list-item__right">
          {age && (
            <span
              className={`incident-age${isUrgentAge ? " incident-age--urgent" : ""}`}
              title={formatDateTime(ts)}
            >
              {isUrgentAge ? "⚠ " : ""}{age}
            </span>
          )}
          <PriorityBadge value={incident.severity} />
        </div>
      </div>

      <div className="incident-list-item__meta">
        <IncidentKindBadge kind={incident.kind} />
        {(incident.engines || []).map((eng) => (
          <IncidentEngineBadge key={eng} engine={eng} />
        ))}
        {hasCves ? <span className="incident-chip">CVE</span> : null}
        {incident.fp_likely && (
          <span className="incident-chip incident-chip--fp" title={`Score FP: ${incident.fp_score} — ${(incident.fp_reasons || []).join(", ")}`}>
            ~ FP probable
          </span>
        )}
        <span
          className="incident-status-btn"
          style={{ "--status-color": current.color }}
          onClick={handleStatusClick}
          title={`Passer à : ${next.label}`}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === "Enter" && handleStatusClick(e)}
        >
          <span className="incident-status-dot" style={{ background: current.color }} />
          {current.label}
        </span>
        {isOpen && (
          <span
            className="incident-takeover-btn"
            onClick={handleTakeOver}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && handleTakeOver(e)}
            title="Prendre en charge cet incident"
          >
            Prendre en charge
          </span>
        )}
      </div>

      <p className="incident-list-item__description">
        {incident.description || "Aucune description disponible."}
      </p>

      <div className="incident-list-item__meta">
        {count > 0 && (
          <span className="incident-signals-badge">{count} signal{count > 1 ? "s" : ""}</span>
        )}
        <span>Dernier signal : {formatDateTime(incident.last_seen || incident.timestamp)}</span>
      </div>
    </button>
  );
}