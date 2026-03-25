import React from "react";
import { KIND_LABELS } from "../lib/incidentConstants";
import {
  getPriorityLabel,
  normalizeEngine,
  normalizeKind,
} from "../lib/incidentNormalization";

export function PriorityBadge({ value }) {
  const label = getPriorityLabel(value);

  return (
    <span className={`incident-badge incident-badge--${label}`}>
      {label}
    </span>
  );
}

export function IncidentKindBadge({ kind }) {
  const normalized = normalizeKind(kind);
  const label = KIND_LABELS[normalized] || KIND_LABELS.generic;

  return (
    <span
      className={`incident-chip incident-chip--kind incident-chip--${normalized}`}
    >
      {label}
    </span>
  );
}

export function IncidentEngineBadge({ engine }) {
  const normalized = normalizeEngine(engine);
  const label = normalized === "non précisé" ? "moteur non précisé" : normalized;

  return (
    <span
      className={`incident-chip incident-chip--engine incident-chip--${normalized.replace(
        /\s+/g,
        "-"
      )}`}
    >
      {label}
    </span>
  );
}