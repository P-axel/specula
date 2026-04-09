import React, { useRef, useState } from "react";
import { useIncidentStore } from "../hooks/useIncidentStore";
import { KIND_LABELS } from "../lib/incidentConstants";
import {
  formatDateTime,
  formatPairsList,
  formatRenderableValue,
} from "../lib/incidentFormatters";
import {
  PriorityBadge,
  IncidentEngineBadge,
  IncidentKindBadge,
} from "./IncidentBadges";

// ── Helpers ───────────────────────────────────────────────────────────────────

function DetailRow({ label, value }) {
  return (
    <div className="incident-detail-row">
      <div className="incident-detail-label">{label}</div>
      <div className="incident-detail-value">{formatRenderableValue(value)}</div>
    </div>
  );
}

function normalizeList(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (value == null || value === "") return [];
  return [value];
}

function DetailTagList({ title, items, emptyLabel }) {
  const normalizedItems = normalizeList(items);
  return (
    <div className="incident-detail-block">
      <h4>{title}</h4>
      {normalizedItems.length ? (
        <div className="incident-chip-list">
          {normalizedItems.map((item, index) => (
            <span className="incident-chip" key={`${title}-${index}-${String(item)}`}>
              {String(item)}
            </span>
          ))}
        </div>
      ) : (
        <p className="empty-state">{emptyLabel}</p>
      )}
    </div>
  );
}

function SourceBadge({ source }) {
  if (!source) return null;
  const normalized = String(source).toLowerCase();
  const label =
    normalized === "correlated" ? "Corrélé"
    : normalized === "detection_fallback" ? "Détection"
    : normalized;
  return <span className="incident-chip">{label}</span>;
}

// ── Status selector ───────────────────────────────────────────────────────────

const STATUS_OPTIONS = [
  { value: "open", label: "Ouvert", color: "#ff2244" },
  { value: "investigating", label: "En cours", color: "#ffaa00" },
  { value: "resolved", label: "Résolu", color: "#39ff14" },
];

function StatusSelector({ status, onChange }) {
  const idx = STATUS_OPTIONS.findIndex((o) => o.value === status);
  const current = idx >= 0 ? STATUS_OPTIONS[idx] : STATUS_OPTIONS[0];
  const next = STATUS_OPTIONS[(idx + 1) % STATUS_OPTIONS.length];

  return (
    <button
      type="button"
      className="incident-status-btn"
      style={{ "--status-color": current.color }}
      onClick={() => onChange(next.value)}
      title={`Passer à : ${next.label}`}
    >
      <span className="incident-status-dot" style={{ background: current.color }} />
      {current.label}
    </button>
  );
}

// ── Historique des statuts ────────────────────────────────────────────────────

const STATUS_LABELS_MAP = {
  open: "Ouvert",
  investigating: "En cours",
  resolved: "Résolu",
  false_positive: "Faux positif",
};

function StatusHistory({ incidentId }) {
  const { statusHistory } = useIncidentStore(incidentId);
  if (!statusHistory?.length) return null;

  return (
    <div className="incident-detail-block incident-status-history">
      <h4>Historique des statuts</h4>
      <div className="incident-history-list">
        {[...statusHistory].reverse().map((entry, i) => (
          <div key={i} className="incident-history-item">
            <span className="incident-history-from">
              {STATUS_LABELS_MAP[entry.from] ?? entry.from}
            </span>
            <span className="incident-history-arrow">→</span>
            <span className="incident-history-to">
              {STATUS_LABELS_MAP[entry.to] ?? entry.to}
            </span>
            <span className="incident-history-ts">
              {new Date(entry.ts).toLocaleString("fr-FR")}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Notes & pièces jointes ────────────────────────────────────────────────────

function IncidentNotes({ incidentId }) {
  const {
    comments, attachments,
    addComment, deleteComment,
    addAttachment, deleteAttachment, downloadAttachment,
  } = useIncidentStore(incidentId);

  const [draft, setDraft] = useState("");
  const fileInputRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    addComment(draft);
    setDraft("");
  };

  return (
    <div className="incident-detail-block incident-notes">
      <h4>Notes &amp; pièces jointes</h4>

      {/* Comments */}
      <form className="incident-notes-form" onSubmit={handleSubmit}>
        <textarea
          className="incident-notes-input"
          placeholder="Ajouter une note..."
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
        />
        <button type="submit" className="incident-notes-submit" disabled={!draft.trim()}>
          Enregistrer
        </button>
      </form>

      {comments.length > 0 && (
        <div className="incident-note-list">
          {comments.map((c) => (
            <div key={c.id} className="incident-note-item">
              <div className="incident-note-text">{c.text}</div>
              <div className="incident-note-meta">
                <span>{new Date(c.ts).toLocaleString("fr-FR")}</span>
                <button
                  type="button"
                  className="incident-note-delete"
                  onClick={() => deleteComment(c.id)}
                  title="Supprimer"
                >
                  ×
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Attachments */}
      <div className="incident-attachments">
        <button
          type="button"
          className="incident-attach-btn"
          onClick={() => fileInputRef.current?.click()}
        >
          + Joindre un fichier
        </button>
        <input
          ref={fileInputRef}
          type="file"
          style={{ display: "none" }}
          onChange={(e) => { addAttachment(e.target.files[0]); e.target.value = ""; }}
        />
        {attachments.length > 0 && (
          <div className="incident-attachment-list">
            {attachments.map((a) => (
              <div key={a.id} className="incident-attachment-item">
                <button
                  type="button"
                  className="incident-attachment-name"
                  onClick={() => downloadAttachment(a)}
                  title="Télécharger"
                >
                  {a.name}
                </button>
                <span className="incident-attachment-size">
                  {(a.size / 1024).toFixed(1)} Ko
                </span>
                <button
                  type="button"
                  className="incident-note-delete"
                  onClick={() => deleteAttachment(a.id)}
                  title="Supprimer"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── GeoIP block ───────────────────────────────────────────────────────────────

function GeoLabel({ geo }) {
  if (!geo) return <span className="incident-geo--unknown">-</span>;
  const parts = [geo.city, geo.country_name].filter(Boolean);
  const label = parts.length ? parts.join(", ") : geo.country_code || "-";
  const flag = geo.country_code
    ? String.fromCodePoint(
        ...geo.country_code
          .toUpperCase()
          .split("")
          .map((c) => 0x1f1e0 + c.charCodeAt(0) - 65)
      )
    : "";
  return (
    <span className="incident-geo">
      {flag && <span className="incident-geo__flag">{flag}</span>}
      {label}
    </span>
  );
}

// ── MITRE block ───────────────────────────────────────────────────────────────

function MitreBlock({ incident }) {
  const techniqueId = incident.mitre_technique_id;
  const techniqueName = incident.mitre_technique_name;
  const tactic = incident.mitre_tactic;
  const techniques = normalizeList(incident.mitre_techniques || incident.mitre);

  const hasRichData = techniqueId || techniqueName || tactic;

  if (!hasRichData && !techniques.length) {
    return (
      <div className="incident-detail-block">
        <h4>MITRE ATT&amp;CK</h4>
        <p className="empty-state">Aucune référence MITRE disponible.</p>
      </div>
    );
  }

  return (
    <div className="incident-detail-block">
      <h4>MITRE ATT&amp;CK</h4>
      {hasRichData && (
        <div className="incident-mitre-card">
          {tactic && (
            <div className="incident-mitre-row">
              <span className="incident-mitre-label">Tactique</span>
              <span className="incident-mitre-value incident-mitre-tactic">{tactic}</span>
            </div>
          )}
          {techniqueId && (
            <div className="incident-mitre-row">
              <span className="incident-mitre-label">Technique</span>
              <span className="incident-mitre-value">
                <span className="incident-chip incident-chip--mitre">{techniqueId}</span>
                {techniqueName && (
                  <span className="incident-mitre-name">{techniqueName}</span>
                )}
              </span>
            </div>
          )}
        </div>
      )}
      {techniques.length > 0 && (
        <div className="incident-chip-list" style={{ marginTop: hasRichData ? 10 : 0 }}>
          {techniques.map((item, index) => (
            <span className="incident-chip incident-chip--mitre" key={`mitre-${index}-${item}`}>
              {String(item)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Network context ───────────────────────────────────────────────────────────

function NetworkBlock({ incident }) {
  if (incident.kind !== "network" && incident.incident_domain !== "network") return null;
  const pairs = formatPairsList(incident.ip_pairs || incident.peer_ips);

  return (
    <>
      <DetailTagList title="Pairs IP" items={pairs} emptyLabel="Aucune paire IP disponible." />
      <div className="incident-detail-block">
        <h4>Contexte réseau</h4>
        <div className="incident-detail-grid">
          <div className="incident-detail-row">
            <div className="incident-detail-label">IP source</div>
            <div className="incident-detail-value incident-ip-geo">
              <code>{incident.src_ip || "-"}</code>
              <GeoLabel geo={incident.src_geo} />
            </div>
          </div>
          <div className="incident-detail-row">
            <div className="incident-detail-label">IP destination</div>
            <div className="incident-detail-value incident-ip-geo">
              <code>{incident.dest_ip || "-"}</code>
              <GeoLabel geo={incident.dest_geo} />
            </div>
          </div>
          <DetailRow label="Signature" value={incident.signature} />
          <DetailRow label="Signature ID" value={incident.signature_id} />
          <DetailRow label="Protocole" value={incident.app_proto} />
          <DetailRow label="Direction" value={incident.direction} />
          <DetailRow label="Flow ID" value={incident.flow_id} />
          <DetailRow label="HTTP host" value={incident.http_host} />
          <DetailRow label="HTTP URL" value={incident.http_url} />
          <DetailRow label="DNS query" value={incident.dns_query} />
          <DetailRow label="TLS SNI" value={incident.tls_sni} />
          <DetailRow label="JA3" value={incident.ja3} />
        </div>
      </div>
    </>
  );
}

// ── Timeline ──────────────────────────────────────────────────────────────────

function TimelineBlock({ timeline }) {
  const items = normalizeList(timeline);
  return (
    <div className="incident-detail-block">
      <h4>Timeline</h4>
      {!items.length ? (
        <p className="empty-state">Aucun événement de timeline disponible.</p>
      ) : (
        <div className="incident-linked-alerts">
          {items.map((entry, index) => (
            <div
              className="incident-linked-alert"
              key={`${entry.timestamp || "timeline"}-${index}`}
            >
              <div className="incident-linked-alert__top">
                <div className="incident-linked-alert__title">
                  {entry.title || "Signal"}
                </div>
                <PriorityBadge value={entry.severity} />
              </div>
              <div className="incident-chip-list" style={{ marginTop: 10, marginBottom: 10 }}>
                {entry.category && <span className="incident-chip">{entry.category}</span>}
                {entry.source_engine && <span className="incident-chip">{entry.source_engine}</span>}
                {entry.user_name && <span className="incident-chip">{entry.user_name}</span>}
                {entry.process_name && <span className="incident-chip">{entry.process_name}</span>}
              </div>
              <div className="incident-linked-alert__meta">
                <span>{formatDateTime(entry.timestamp)}</span>
                <span>{entry.src_ip || "-"}</span>
                <span>{entry.dest_ip || "-"}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

export default function IncidentDetailPanel({ incident, linkedAlerts, onStatusChange }) {
  if (!incident) {
    return (
      <div className="incident-panel-empty">
        <p className="empty-state">
          Sélectionne un incident pour ouvrir sa vue détaillée.
        </p>
      </div>
    );
  }

  const engines = normalizeList(incident.engines);
  const themes = normalizeList(incident.themes);
  const categories = normalizeList(incident.categories || incident.category);
  const cves = normalizeList(incident.cves);
  const users = normalizeList(incident.users || incident.user_name);
  const processes = normalizeList(incident.processes || incident.process_name);
  const files = normalizeList(incident.files);
  const registryKeys = normalizeList(incident.registry_keys);
  const evidence = normalizeList(incident.evidence);
  const timeline = normalizeList(incident.timeline);
  const currentStatus = incident.status ?? "open";

  return (
    <div className="incident-detail-panel">
      {/* Header */}
      <div className="incident-detail-header">
        <div className="incident-detail-kicker">Incident</div>
        <h3>{incident.title || incident.name || "-"}</h3>
      </div>

      {/* Badges row */}
      <div className="incident-chip-list" style={{ marginBottom: 12 }}>
        <PriorityBadge value={incident.severity} />
        <IncidentKindBadge kind={incident.kind || incident.incident_domain} />
        <IncidentEngineBadge
          engine={incident.engine || incident.dominant_engine || engines[0] || incident.provider}
        />
        <SourceBadge source={incident.source} />
      </div>

      <p className="incident-detail-description" style={{ marginTop: 14 }}>
        {formatRenderableValue(incident.description || "-")}
      </p>

      {/* Core fields */}
      <div className="incident-detail-grid">
        <DetailRow
          label="Famille"
          value={
            KIND_LABELS[incident.kind] ||
            KIND_LABELS[incident.incident_domain] ||
            incident.incident_domain ||
            "Autre"
          }
        />
        <DetailRow
          label="Moteur"
          value={
            incident.engine || incident.dominant_engine || incident.provider || engines[0] || "—"
          }
        />
        <DetailRow label="Sévérité" value={incident.severity} />
        <DetailRow label="Score de risque" value={incident.risk_score} />
        <DetailRow label="Confiance" value={incident.confidence} />
        <DetailRow label="Actif" value={incident.asset_name} />
        <DetailRow label="Agent" value={incident.agent_name} />
        <DetailRow label="IP source" value={incident.src_ip} />
        <DetailRow label="IP destination" value={incident.dest_ip} />
        <DetailRow label="Premier vu" value={formatDateTime(incident.first_seen)} />
        <DetailRow label="Dernier vu" value={formatDateTime(incident.last_seen)} />
        <DetailRow
          label="Détections"
          value={incident.detections_count ?? incident.signals_count ?? 0}
        />
      </div>

      {/* GeoIP — shown when IPs are present and geo data is available */}
      {(incident.src_geo || incident.dest_geo) && (
        <div className="incident-detail-block">
          <h4>Géolocalisation</h4>
          <div className="incident-detail-grid">
            {incident.src_geo && (
              <div className="incident-detail-row">
                <div className="incident-detail-label">Source</div>
                <div className="incident-detail-value incident-ip-geo">
                  <code>{incident.src_ip}</code>
                  <GeoLabel geo={incident.src_geo} />
                </div>
              </div>
            )}
            {incident.dest_geo && (
              <div className="incident-detail-row">
                <div className="incident-detail-label">Destination</div>
                <div className="incident-detail-value incident-ip-geo">
                  <code>{incident.dest_ip}</code>
                  <GeoLabel geo={incident.dest_geo} />
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Why it matters */}
      {incident.why_it_matters && (
        <div className="incident-detail-block">
          <h4>Pourquoi c'est important</h4>
          <p className="incident-detail-description">{incident.why_it_matters}</p>
        </div>
      )}

      {/* Recommended actions */}
      {incident.recommended_actions?.length > 0 && (
        <div className="incident-detail-block">
          <h4>Actions recommandées</h4>
          <div className="incident-chip-list">
            {incident.recommended_actions.map((action, index) => (
              <span className="incident-chip" key={`action-${index}`}>{action}</span>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK — enriched block */}
      <MitreBlock incident={incident} />

      <DetailTagList title="Moteurs impliqués" items={engines} emptyLabel="Aucun moteur identifié." />
      <DetailTagList title="Thèmes" items={themes} emptyLabel="Aucun thème disponible." />
      <DetailTagList title="Catégories" items={categories} emptyLabel="Aucune catégorie disponible." />

      {/* Network context */}
      <NetworkBlock incident={incident} />

      {/* Vulnerability */}
      {(incident.package_name || incident.package_version || incident.fixed_version) && (
        <div className="incident-detail-block">
          <h4>Vulnérabilité / package</h4>
          <div className="incident-detail-grid">
            <DetailRow label="Package" value={incident.package_name} />
            <DetailRow label="Version" value={incident.package_version} />
            <DetailRow label="Version corrigée" value={incident.fixed_version} />
          </div>
        </div>
      )}

      <DetailTagList title="CVE associés" items={cves} emptyLabel="Aucun CVE associé." />
      <DetailTagList title="Utilisateurs impliqués" items={users} emptyLabel="Aucun utilisateur identifié." />
      <DetailTagList title="Processus observés" items={processes} emptyLabel="Aucun processus remonté." />
      <DetailTagList title="Fichiers / chemins" items={files} emptyLabel="Aucun fichier remonté." />
      <DetailTagList title="Clés registre" items={registryKeys} emptyLabel="Aucune clé registre remontée." />
      <DetailTagList title="Éléments d'analyse" items={evidence} emptyLabel="Aucun élément complémentaire." />

      <TimelineBlock timeline={timeline} />

      {/* Historique des statuts */}
      <StatusHistory incidentId={incident.id} />

      {/* Notes & pièces jointes */}
      <IncidentNotes incidentId={incident.id} />

      {/* Linked signals */}
      <div className="incident-detail-block">
        <h4>Signaux liés</h4>
        {!linkedAlerts.length ? (
          <p className="empty-state">Aucune alerte liée disponible.</p>
        ) : (
          <div className="incident-linked-alerts">
            {linkedAlerts.map((alert, index) => (
              <div
                className="incident-linked-alert"
                key={alert.id || `${alert.title}-${index}`}
              >
                <div className="incident-linked-alert__top">
                  <div className="incident-linked-alert__title">{alert.title || "-"}</div>
                  <PriorityBadge value={alert.severity} />
                </div>
                <div className="incident-chip-list" style={{ marginTop: 10, marginBottom: 10 }}>
                  <IncidentKindBadge kind={alert.kind} />
                  <IncidentEngineBadge engine={alert.engine} />
                </div>
                <div className="incident-linked-alert__description">
                  {alert.description || "-"}
                </div>
                <div className="incident-linked-alert__meta">
                  <span>{alert.category || "-"}</span>
                  <span>{alert.protocol || "-"}</span>
                  <span>{alert.asset_name || "-"}</span>
                  <span>{formatDateTime(alert.timestamp)}</span>
                </div>
                {(alert.cves?.length || alert.mitre?.length) ? (
                  <div className="incident-chip-list" style={{ marginTop: 10 }}>
                    {alert.cves?.map((cve) => (
                      <span className="incident-chip" key={`${alert.id}-cve-${cve}`}>{cve}</span>
                    ))}
                    {alert.mitre?.map((item) => (
                      <span className="incident-chip incident-chip--mitre" key={`${alert.id}-mitre-${item}`}>
                        {item}
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
