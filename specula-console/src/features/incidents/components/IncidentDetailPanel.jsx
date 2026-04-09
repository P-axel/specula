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

// ── Constantes ────────────────────────────────────────────────────────────────

const SEV_COLORS = {
  critical: "#ff2244",
  high:     "#ff6b00",
  medium:   "#ffaa00",
  low:      "#4fb8ff",
  info:     "#355d78",
};

const STATUS_OPTIONS = [
  { value: "open",           label: "Ouvert",       color: "#ff2244" },
  { value: "investigating",  label: "En cours",     color: "#ffaa00" },
  { value: "resolved",       label: "Résolu",       color: "#39ff14" },
  { value: "false_positive", label: "Faux positif", color: "#7a7a9a" },
];

const STATUS_LABELS_MAP = {
  open:           "Ouvert",
  investigating:  "En cours",
  resolved:       "Résolu",
  false_positive: "Faux positif",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function normalizeList(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (value == null || value === "") return [];
  return [value];
}

/** Retire le suffixe " (asset)" généré par le correlator */
function cleanTitle(title, asset) {
  if (!title) return "-";
  if (asset && title.endsWith(`(${asset})`)) {
    return title.slice(0, -(asset.length + 3)).trim();
  }
  return title;
}

function formatAge(ts) {
  if (!ts) return null;
  const ms = Date.now() - new Date(ts).getTime();
  if (ms < 0) return null;
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  if (h >= 24) return `${Math.floor(h / 24)}j ${h % 24}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function isUrgentAge(incident) {
  const sev = String(incident.severity || "").toLowerCase();
  const status = String(incident.status || "").toLowerCase();
  const ts = incident.first_seen || incident.timestamp;
  if (!ts) return false;
  const ms = Date.now() - new Date(ts).getTime();
  return (sev === "critical" || sev === "high") &&
    (status === "open" || status === "investigating") &&
    ms > 4 * 3_600_000;
}

// ── Section wrapper — n'affiche rien si enfants vides ─────────────────────────

function Section({ title, children, className = "" }) {
  return (
    <div className={`pdp-section ${className}`}>
      {title && <div className="pdp-section__title">{title}</div>}
      {children}
    </div>
  );
}

// ── Header HUD ────────────────────────────────────────────────────────────────

function PanelHeader({ incident }) {
  const sev = String(incident.severity || "info").toLowerCase();
  const sevColor = SEV_COLORS[sev] || SEV_COLORS.info;
  const score = incident.risk_score ?? null;
  const age = formatAge(incident.first_seen || incident.timestamp);
  const urgent = isUrgentAge(incident);
  const title = cleanTitle(incident.title || incident.name, incident.asset_name);

  return (
    <div className="pdp-header" style={{ "--sev-color": sevColor }}>
      <div className="pdp-header__sev-bar" />
      <div className="pdp-header__body">
        <div className="pdp-header__left">
          <div className="pdp-header__kicker">Incident</div>
          <h3 className="pdp-header__title">{title}</h3>
          <div className="pdp-header__badges">
            <PriorityBadge value={incident.severity} />
            <IncidentKindBadge kind={incident.kind || incident.incident_domain} />
            <IncidentEngineBadge
              engine={incident.engine || incident.dominant_engine ||
                normalizeList(incident.engines)[0] || incident.provider}
            />
            {incident.source === "correlated" || incident.source === "detection_fallback" ? (
              <span className="incident-chip incident-chip--correlated" style={{ fontSize: "0.75rem", padding: "4px 10px" }}>
                {incident.source === "correlated" ? "Corrélé" : "Détection"}
              </span>
            ) : null}
          </div>
        </div>

        <div className="pdp-header__right">
          {score !== null && (
            <div className="pdp-score" style={{ "--sev-color": sevColor }}>
              <div className="pdp-score__value">{score}</div>
              <div className="pdp-score__label">/ 100</div>
            </div>
          )}
          {age && (
            <div className={`pdp-age${urgent ? " pdp-age--urgent" : ""}`}>
              {urgent ? "⚠ " : ""}{age}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Barre de statut ───────────────────────────────────────────────────────────

function StatusBar({ status, onStatusChange }) {
  return (
    <div className="pdp-status-bar">
      {STATUS_OPTIONS.map((opt) => {
        const active = status === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            className={`pdp-status-btn${active ? " pdp-status-btn--active" : ""}`}
            style={{ "--status-color": opt.color }}
            onClick={() => !active && onStatusChange(opt.value)}
            disabled={active}
          >
            <span className="pdp-status-dot" />
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

// ── Strip métriques ───────────────────────────────────────────────────────────

function MetricsStrip({ incident }) {
  const count = incident.signals_count ?? incident.detections_count ?? null;
  const conf = incident.confidence != null
    ? `${Math.round(Number(incident.confidence) * 100)}%`
    : null;
  const engine = incident.dominant_engine ||
    normalizeList(incident.engines)[0] || incident.provider || null;

  const items = [
    count != null && { icon: "⚡", label: `${count} signal${count > 1 ? "s" : ""}` },
    incident.asset_name && { icon: "🖥", label: incident.asset_name },
    conf && { icon: "📊", label: `Conf. ${conf}` },
    engine && { icon: "🔍", label: engine.toUpperCase() },
    incident.src_ip && { icon: "→", label: `${incident.src_ip} → ${incident.dest_ip || "?"}` },
  ].filter(Boolean);

  if (!items.length) return null;

  return (
    <div className="pdp-metrics">
      {items.map((item, i) => (
        <span key={i} className="pdp-metric">
          <span className="pdp-metric__icon">{item.icon}</span>
          <span className="pdp-metric__label">{item.label}</span>
        </span>
      ))}
    </div>
  );
}

// ── Flux réseau ───────────────────────────────────────────────────────────────

function NetworkFlow({ incident }) {
  const isNetwork = incident.kind === "network" || incident.incident_domain === "network";
  if (!isNetwork || (!incident.src_ip && !incident.dest_ip)) return null;

  const proto = incident.app_proto || incident.protocol || null;
  const dnsQuery = incident.dns_query || null;
  const httpHost = incident.http_host || null;
  const tlsSni = incident.tls_sni || null;
  const pairs = formatPairsList(incident.ip_pairs || incident.peer_ips);

  return (
    <Section title="Flux réseau" className="pdp-section--network">
      <div className="pdp-flow">
        <div className="pdp-flow__node">
          <div className="pdp-flow__ip">{incident.src_ip || "?"}</div>
          {incident.src_geo && (
            <div className="pdp-flow__geo">{geoLabel(incident.src_geo)}</div>
          )}
          <div className="pdp-flow__role">Source</div>
        </div>

        <div className="pdp-flow__arrow">
          <div className="pdp-flow__line" />
          {proto && <div className="pdp-flow__proto">{proto.toUpperCase()}</div>}
          <div className="pdp-flow__arrowhead">→</div>
        </div>

        <div className="pdp-flow__node pdp-flow__node--dest">
          <div className="pdp-flow__ip">{incident.dest_ip || "?"}</div>
          {incident.dest_geo && (
            <div className="pdp-flow__geo">{geoLabel(incident.dest_geo)}</div>
          )}
          <div className="pdp-flow__role">Destination</div>
        </div>
      </div>

      {(dnsQuery || httpHost || tlsSni || incident.http_url || incident.ja3) && (
        <div className="pdp-flow__meta">
          {dnsQuery   && <FlowMetaRow label="DNS"  value={dnsQuery} />}
          {httpHost   && <FlowMetaRow label="Host" value={httpHost} />}
          {incident.http_url && <FlowMetaRow label="URL"  value={incident.http_url} />}
          {tlsSni     && <FlowMetaRow label="SNI"  value={tlsSni} />}
          {incident.ja3 && <FlowMetaRow label="JA3"  value={incident.ja3} mono />}
        </div>
      )}

      {pairs.length > 0 && (
        <div className="pdp-flow__pairs">
          {pairs.map((p, i) => (
            <span key={i} className="pdp-flow__pair">{p}</span>
          ))}
        </div>
      )}
    </Section>
  );
}

function FlowMetaRow({ label, value, mono }) {
  return (
    <div className="pdp-flow-meta-row">
      <span className="pdp-flow-meta-label">{label}</span>
      <span className={`pdp-flow-meta-value${mono ? " pdp-flow-meta-value--mono" : ""}`}>{value}</span>
    </div>
  );
}

function geoLabel(geo) {
  if (!geo) return null;
  const flag = geo.country_code
    ? String.fromCodePoint(...geo.country_code.toUpperCase().split("").map((c) => 0x1f1e0 + c.charCodeAt(0) - 65))
    : "";
  const parts = [geo.city, geo.country_name].filter(Boolean);
  return `${flag} ${parts.join(", ") || geo.country_code || ""}`.trim();
}

// ── Threat Intel ──────────────────────────────────────────────────────────────

function ThreatIntelBlock({ threatIntel }) {
  if (!threatIntel?.hits?.length) return null;
  const bad = threatIntel.is_known_bad;

  return (
    <div className={`pdp-ti${bad ? " pdp-ti--bad" : " pdp-ti--warn"}`}>
      <div className="pdp-ti__header">
        <span className="pdp-ti__badge">
          {bad ? "⚠ IoC CONNU MALVEILLANT" : "⚠ Réputation dégradée"}
        </span>
        {threatIntel.reputation_score > 0 && (
          <span className="pdp-ti__score">Score {threatIntel.reputation_score}/100</span>
        )}
      </div>
      <div className="pdp-ti__hits">
        {threatIntel.hits.map((hit, i) => (
          <div key={i} className="pdp-ti__hit">
            <code className="pdp-ti__ioc">{hit.ioc}</code>
            <div className="pdp-ti__details">
              {hit.source && <span className="pdp-ti__tag">{hit.source}</span>}
              {hit.malware && <span className="pdp-ti__malware">{hit.malware}</span>}
              {hit.threat_type && <span className="pdp-ti__tag">{hit.threat_type}</span>}
              {hit.suspicious_tags?.map((t) => (
                <span key={t} className="pdp-ti__tag pdp-ti__tag--sus">{t}</span>
              ))}
              {hit.vulns?.slice(0, 3).map((v) => (
                <span key={v} className="pdp-ti__cve">{v}</span>
              ))}
              {hit.vulns?.length > 3 && (
                <span className="pdp-ti__tag">+{hit.vulns.length - 3} CVE</span>
              )}
              {hit.confidence > 0 && <span className="pdp-ti__tag">{hit.confidence}% confiance</span>}
              {hit.urls_count > 0 && <span className="pdp-ti__tag pdp-ti__tag--sus">{hit.urls_count} URLs malveillantes</span>}
              {hit.ports?.length > 0 && (
                <span className="pdp-ti__tag">{hit.ports.slice(0, 5).join(", ")} ports ouverts</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── MITRE ─────────────────────────────────────────────────────────────────────

function MitreBlock({ incident }) {
  const techniqueId   = incident.mitre_technique_id;
  const techniqueName = incident.mitre_technique_name;
  const tactic        = incident.mitre_tactic;
  const techniques    = normalizeList(incident.mitre_techniques || incident.mitre);

  if (!techniqueId && !techniqueName && !tactic && !techniques.length) return null;

  return (
    <Section title="MITRE ATT&CK">
      {(tactic || techniqueId) && (
        <div className="pdp-mitre-card">
          {tactic && (
            <div className="pdp-mitre-row">
              <span className="pdp-mitre-label">Tactique</span>
              <span className="pdp-mitre-tactic">{tactic}</span>
            </div>
          )}
          {techniqueId && (
            <div className="pdp-mitre-row">
              <span className="pdp-mitre-label">Technique</span>
              <span className="incident-chip incident-chip--mitre">{techniqueId}</span>
              {techniqueName && <span className="pdp-mitre-name">{techniqueName}</span>}
            </div>
          )}
        </div>
      )}
      {techniques.length > 0 && (
        <div className="incident-chip-list" style={{ marginTop: 8 }}>
          {techniques.map((t, i) => (
            <span key={i} className="incident-chip incident-chip--mitre">{String(t)}</span>
          ))}
        </div>
      )}
    </Section>
  );
}

// ── Timeline ──────────────────────────────────────────────────────────────────

function TimelineBlock({ timeline }) {
  const items = normalizeList(timeline);
  if (!items.length) return null;

  return (
    <Section title={`Timeline · ${items.length} événement${items.length > 1 ? "s" : ""}`}>
      <div className="pdp-timeline">
        {items.map((entry, i) => (
          <div key={i} className="pdp-timeline__item">
            <div className="pdp-timeline__dot" />
            <div className="pdp-timeline__body">
              <div className="pdp-timeline__title">{entry.title || "Signal"}</div>
              <div className="pdp-timeline__meta">
                <span>{formatDateTime(entry.timestamp)}</span>
                {entry.src_ip && <span>{entry.src_ip}</span>}
                {entry.category && <span>{entry.category}</span>}
                {entry.source_engine && <span>{entry.source_engine}</span>}
              </div>
            </div>
            <PriorityBadge value={entry.severity} />
          </div>
        ))}
      </div>
    </Section>
  );
}

// ── Historique statuts ────────────────────────────────────────────────────────

function StatusHistory({ incidentId }) {
  const { statusHistory } = useIncidentStore(incidentId);
  // Ne montrer que les transitions réelles (from non nul)
  const real = (statusHistory || []).filter((e) => e.from && e.to && e.from !== e.to);
  if (!real.length) return null;

  return (
    <Section title="Historique">
      <div className="pdp-history">
        {[...real].reverse().map((entry, i) => (
          <div key={i} className="pdp-history__item">
            <span className="pdp-history__from">{STATUS_LABELS_MAP[entry.from] ?? entry.from}</span>
            <span className="pdp-history__arrow">→</span>
            <span className="pdp-history__to">{STATUS_LABELS_MAP[entry.to] ?? entry.to}</span>
            <span className="pdp-history__ts">{new Date(entry.ts).toLocaleString("fr-FR")}</span>
          </div>
        ))}
      </div>
    </Section>
  );
}

// ── Notes ─────────────────────────────────────────────────────────────────────

function NotesBlock({ incidentId }) {
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
    <Section title="Notes & pièces jointes">
      <form className="pdp-notes-form" onSubmit={handleSubmit}>
        <textarea
          className="pdp-notes-input"
          placeholder="Ajouter une note d'analyse..."
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
        />
        <div className="pdp-notes-actions">
          <button
            type="button"
            className="pdp-attach-btn"
            onClick={() => fileInputRef.current?.click()}
          >
            + Joindre
          </button>
          <input
            ref={fileInputRef}
            type="file"
            style={{ display: "none" }}
            onChange={(e) => { addAttachment(e.target.files[0]); e.target.value = ""; }}
          />
          <button type="submit" className="pdp-notes-submit" disabled={!draft.trim()}>
            Enregistrer
          </button>
        </div>
      </form>

      {comments.length > 0 && (
        <div className="pdp-note-list">
          {comments.map((c) => (
            <div key={c.id} className="pdp-note-item">
              <div className="pdp-note-text">{c.text}</div>
              <div className="pdp-note-meta">
                <span>{new Date(c.ts).toLocaleString("fr-FR")}</span>
                <button
                  type="button"
                  className="pdp-note-delete"
                  onClick={() => deleteComment(c.id)}
                  title="Supprimer"
                >×</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {attachments.length > 0 && (
        <div className="pdp-attachment-list">
          {attachments.map((a) => (
            <div key={a.id} className="pdp-attachment-item">
              <button
                type="button"
                className="pdp-attachment-name"
                onClick={() => downloadAttachment(a)}
              >{a.name}</button>
              <span className="pdp-attachment-size">{(a.size / 1024).toFixed(1)} Ko</span>
              <button
                type="button"
                className="pdp-note-delete"
                onClick={() => deleteAttachment(a.id)}
              >×</button>
            </div>
          ))}
        </div>
      )}
    </Section>
  );
}

// ── Signaux liés ──────────────────────────────────────────────────────────────

function LinkedSignals({ linkedAlerts }) {
  const [expanded, setExpanded] = useState(false);
  if (!linkedAlerts?.length) return null;

  const shown = expanded ? linkedAlerts : linkedAlerts.slice(0, 3);

  return (
    <Section title={`Signaux liés · ${linkedAlerts.length}`}>
      <div className="pdp-signals">
        {shown.map((alert, i) => (
          <div key={alert.id || i} className="pdp-signal">
            <div className="pdp-signal__top">
              <span className="pdp-signal__title">{alert.title || "-"}</span>
              <PriorityBadge value={alert.severity} />
            </div>
            <div className="pdp-signal__meta">
              {alert.category && <span>{alert.category}</span>}
              {alert.asset_name && <span>{alert.asset_name}</span>}
              <span>{formatDateTime(alert.timestamp)}</span>
            </div>
          </div>
        ))}
      </div>
      {linkedAlerts.length > 3 && (
        <button
          type="button"
          className="pdp-expand-btn"
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded ? "Réduire" : `Voir les ${linkedAlerts.length - 3} signaux restants`}
        </button>
      )}
    </Section>
  );
}

// ── Composant principal ───────────────────────────────────────────────────────

export default function IncidentDetailPanel({ incident, linkedAlerts, onStatusChange }) {
  if (!incident) {
    return (
      <div className="incident-panel-empty">
        <p className="empty-state">Sélectionne un incident pour l'analyser.</p>
      </div>
    );
  }

  const sev = String(incident.severity || "info").toLowerCase();
  const sevColor = SEV_COLORS[sev] || SEV_COLORS.info;
  const currentStatus = incident.status ?? "open";

  const cves       = normalizeList(incident.cves);
  const users      = normalizeList(incident.users || incident.user_name);
  const processes  = normalizeList(incident.processes || incident.process_name);
  const files      = normalizeList(incident.files);
  const timeline   = normalizeList(incident.timeline);

  return (
    <div className="incident-detail-panel" style={{ "--sev-color": sevColor }}>

      {/* ── Header ── */}
      <PanelHeader incident={incident} />

      {/* ── Status bar ── */}
      <StatusBar
        status={currentStatus}
        onStatusChange={(newStatus) => onStatusChange?.(incident.id, newStatus)}
      />

      {/* ── Key metrics ── */}
      <MetricsStrip incident={incident} />

      {/* ── Threat Intelligence ── */}
      <ThreatIntelBlock threatIntel={incident.threat_intel} />

      {/* ── Description ── */}
      {incident.description && (
        <p className="pdp-description">{incident.description}</p>
      )}

      {/* ── Flux réseau ── */}
      <NetworkFlow incident={incident} />

      {/* ── Pourquoi c'est important ── */}
      {incident.why_it_matters && (
        <Section title="Pourquoi c'est important">
          <p className="pdp-why">{incident.why_it_matters}</p>
        </Section>
      )}

      {/* ── Actions recommandées ── */}
      {incident.recommended_actions?.length > 0 && (
        <Section title="Actions recommandées">
          <div className="pdp-actions">
            {incident.recommended_actions.map((action, i) => (
              <div key={i} className="pdp-action-item">
                <span className="pdp-action-bullet">→</span>
                {action}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── MITRE ATT&CK ── */}
      <MitreBlock incident={incident} />

      {/* ── Timeline ── */}
      <TimelineBlock timeline={timeline} />

      {/* ── CVEs ── */}
      {cves.length > 0 && (
        <Section title="CVEs associés">
          <div className="incident-chip-list">
            {cves.map((cve) => (
              <span key={cve} className="incident-chip pdp-cve-chip">{cve}</span>
            ))}
          </div>
        </Section>
      )}

      {/* ── Vulnérabilité package ── */}
      {(incident.package_name || incident.package_version) && (
        <Section title="Package vulnérable">
          <div className="pdp-pkg">
            <span className="pdp-pkg__name">{incident.package_name}</span>
            {incident.package_version && <span className="pdp-pkg__ver">v{incident.package_version}</span>}
            {incident.fixed_version && (
              <span className="pdp-pkg__fix">→ corrigé en v{incident.fixed_version}</span>
            )}
          </div>
        </Section>
      )}

      {/* ── Utilisateurs / Processus ── */}
      {users.length > 0 && (
        <Section title="Utilisateurs impliqués">
          <div className="incident-chip-list">
            {users.map((u, i) => <span key={i} className="incident-chip">{u}</span>)}
          </div>
        </Section>
      )}
      {processes.length > 0 && (
        <Section title="Processus observés">
          <div className="incident-chip-list">
            {processes.map((p, i) => <span key={i} className="incident-chip">{p}</span>)}
          </div>
        </Section>
      )}
      {files.length > 0 && (
        <Section title="Fichiers / chemins">
          <div className="incident-chip-list">
            {files.map((f, i) => <span key={i} className="incident-chip">{f}</span>)}
          </div>
        </Section>
      )}

      {/* ── Historique des statuts ── */}
      <StatusHistory incidentId={incident.id} />

      {/* ── Notes & pièces jointes ── */}
      <NotesBlock incidentId={incident.id} />

      {/* ── Signaux liés ── */}
      <LinkedSignals linkedAlerts={linkedAlerts} />

    </div>
  );
}
