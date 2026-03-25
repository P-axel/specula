import React from "react";
import { formatDateTime } from "../lib/incidentFormatters";
import {
  PriorityBadge,
  IncidentKindBadge,
  IncidentEngineBadge,
} from "./IncidentBadges";

export default function IncidentListItem({
  incident,
  isSelected,
  onSelect,
}) {
  const count = incident.detections_count ?? 0;
  const hasCves = Array.isArray(incident.cves) && incident.cves.length > 0;

  return (
    <button
      type="button"
      className={`incident-list-item ${isSelected ? "is-selected" : ""}`}
      onClick={() => onSelect(incident)}
    >
      <div className="incident-list-item__top">
        <div className="incident-list-item__heading">
          <div className="incident-list-item__title">{incident.title || "-"}</div>
          <div className="incident-list-item__subtitle">
            {incident.asset_name || "Actif non identifié"}
          </div>
        </div>

        <PriorityBadge value={incident.severity} />
      </div>

      <div className="incident-list-item__meta">
        <IncidentKindBadge kind={incident.kind} />
        <IncidentEngineBadge engine={incident.engine} />
        {hasCves ? <span className="incident-chip">CVE</span> : null}
      </div>

      <p className="incident-list-item__description">
        {incident.description || "Aucune description disponible."}
      </p>

      <div className="incident-list-item__meta">
        <span>{count} signal(s)</span>
        <span>{formatDateTime(incident.last_seen || incident.timestamp)}</span>
      </div>
    </button>
  );
}