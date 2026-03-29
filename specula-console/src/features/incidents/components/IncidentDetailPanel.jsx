import React from "react";
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

function DetailRow({ label, value }) {
  return (
    <div className="incident-detail-row">
      <div className="incident-detail-label">{label}</div>
      <div className="incident-detail-value">{formatRenderableValue(value)}</div>
    </div>
  );
}

function normalizeList(value) {
  if (Array.isArray(value)) {
    return value.filter(Boolean);
  }
  if (value == null || value === "") {
    return [];
  }
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
    normalized === "correlated"
      ? "Corrélé"
      : normalized === "detection_fallback"
      ? "Détection"
      : normalized;

  return <span className="incident-chip">{label}</span>;
}

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

              <div
                className="incident-chip-list"
                style={{ marginTop: 10, marginBottom: 10 }}
              >
                {entry.category ? (
                  <span className="incident-chip">{entry.category}</span>
                ) : null}
                {entry.source_engine ? (
                  <span className="incident-chip">{entry.source_engine}</span>
                ) : null}
                {entry.user_name ? (
                  <span className="incident-chip">{entry.user_name}</span>
                ) : null}
                {entry.process_name ? (
                  <span className="incident-chip">{entry.process_name}</span>
                ) : null}
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

export default function IncidentDetailPanel({ incident, linkedAlerts }) {
  if (!incident) {
    return (
      <div className="incident-panel-empty">
        <p className="empty-state">
          Sélectionne un incident pour ouvrir sa vue détaillée.
        </p>
      </div>
    );
  }

  const pairs = formatPairsList(incident.ip_pairs || incident.peer_ips);
  const engines = normalizeList(incident.engines);
  const themes = normalizeList(incident.themes);
  const categories = normalizeList(incident.categories || incident.category);
  const cves = normalizeList(incident.cves);
  const mitre = normalizeList(incident.mitre_techniques || incident.mitre);
  const users = normalizeList(incident.users || incident.user_name);
  const processes = normalizeList(incident.processes || incident.process_name);
  const files = normalizeList(incident.files);
  const registryKeys = normalizeList(incident.registry_keys);
  const evidence = normalizeList(incident.evidence);
  const timeline = normalizeList(incident.timeline);

  return (
    <div className="incident-detail-panel">
      <div className="incident-detail-header">
        <div className="incident-detail-kicker">Incident</div>
        <h3>{incident.title || incident.name || "-"}</h3>
      </div>

      <div className="incident-chip-list" style={{ marginBottom: 16 }}>
        <PriorityBadge value={incident.severity} />
        <IncidentKindBadge kind={incident.kind || incident.incident_domain} />
        <IncidentEngineBadge
          engine={
            incident.engine ||
            incident.dominant_engine ||
            engines[0] ||
            incident.provider
          }
        />
        <SourceBadge source={incident.source} />
      </div>

      <p className="incident-detail-description">
        {formatRenderableValue(incident.description || "-")}
      </p>

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
          label="Moteur de détection"
          value={
            incident.engine ||
            incident.dominant_engine ||
            incident.provider ||
            engines[0] ||
            "Moteur non identifié"
          }
        />
        <DetailRow label="Sévérité" value={incident.severity} />
        <DetailRow label="Priorité" value={incident.priority} />
        <DetailRow label="Score" value={incident.risk_score} />
        <DetailRow label="Confiance" value={incident.confidence} />
        <DetailRow label="Actif" value={incident.asset_name} />
        <DetailRow label="Catégorie" value={incident.category || incident.dominant_category} />
        <DetailRow label="Type" value={incident.event_type || incident.type} />
        <DetailRow label="Statut" value={incident.status} />
        <DetailRow label="Agent" value={incident.agent_name} />
        <DetailRow label="Agent ID" value={incident.agent_id} />
        <DetailRow label="Utilisateur principal" value={incident.user_name} />
        <DetailRow label="Processus principal" value={incident.process_name} />
        <DetailRow label="IP source" value={incident.src_ip} />
        <DetailRow label="IP destination" value={incident.dest_ip} />
        <DetailRow label="Premier vu" value={formatDateTime(incident.first_seen)} />
        <DetailRow label="Dernier vu" value={formatDateTime(incident.last_seen)} />
        <DetailRow
          label="Détections"
          value={incident.detections_count ?? incident.signals_count ?? 0}
        />
      </div>

      {incident.why_it_matters ? (
        <div className="incident-detail-block">
          <h4>Pourquoi c’est important</h4>
          <p className="incident-detail-description">{incident.why_it_matters}</p>
        </div>
      ) : null}

      {incident.recommended_actions?.length ? (
        <div className="incident-detail-block">
          <h4>Actions recommandées</h4>
          <div className="incident-chip-list">
            {incident.recommended_actions.map((action, index) => (
              <span className="incident-chip" key={`action-${index}`}>
                {action}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      <DetailTagList
        title="Moteurs impliqués"
        items={engines}
        emptyLabel="Aucun moteur identifié."
      />

      <DetailTagList
        title="Thèmes"
        items={themes}
        emptyLabel="Aucun thème disponible."
      />

      <DetailTagList
        title="Catégories"
        items={categories}
        emptyLabel="Aucune catégorie disponible."
      />

      {incident.kind === "network" || incident.incident_domain === "network" ? (
        <>
          <DetailTagList
            title="Pairs IP"
            items={pairs}
            emptyLabel="Aucune paire IP disponible."
          />

          <div className="incident-detail-block">
            <h4>Détails réseau</h4>
            <div className="incident-detail-grid">
              <DetailRow label="Signature" value={incident.signature} />
              <DetailRow label="Signature ID" value={incident.signature_id} />
              <DetailRow label="Protocole applicatif" value={incident.app_proto} />
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
      ) : null}

      {(incident.package_name ||
        incident.package_version ||
        incident.fixed_version) && (
        <div className="incident-detail-block">
          <h4>Vulnérabilité / package</h4>
          <div className="incident-detail-grid">
            <DetailRow label="Package" value={incident.package_name} />
            <DetailRow label="Version" value={incident.package_version} />
            <DetailRow label="Version corrigée" value={incident.fixed_version} />
          </div>
        </div>
      )}

      <DetailTagList
        title="CVE associés"
        items={cves}
        emptyLabel="Aucun CVE associé."
      />

      <DetailTagList
        title="MITRE / ATT&CK"
        items={mitre}
        emptyLabel="Aucune référence MITRE disponible."
      />

      <DetailTagList
        title="Utilisateurs impliqués"
        items={users}
        emptyLabel="Aucun utilisateur identifié."
      />

      <DetailTagList
        title="Processus observés"
        items={processes}
        emptyLabel="Aucun processus remonté."
      />

      <DetailTagList
        title="Fichiers / chemins"
        items={files}
        emptyLabel="Aucun fichier remonté."
      />

      <DetailTagList
        title="Clés registre"
        items={registryKeys}
        emptyLabel="Aucune clé registre remontée."
      />

      <DetailTagList
        title="Éléments d'analyse"
        items={evidence}
        emptyLabel="Aucun élément complémentaire."
      />

      <TimelineBlock timeline={timeline} />

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
                  <div className="incident-linked-alert__title">
                    {alert.title || "-"}
                  </div>
                  <PriorityBadge value={alert.severity} />
                </div>

                <div
                  className="incident-chip-list"
                  style={{ marginTop: 10, marginBottom: 10 }}
                >
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

                {alert.cves?.length || alert.mitre?.length ? (
                  <div className="incident-chip-list" style={{ marginTop: 10 }}>
                    {alert.cves?.map((cve) => (
                      <span className="incident-chip" key={`${alert.id}-cve-${cve}`}>
                        {cve}
                      </span>
                    ))}
                    {alert.mitre?.map((item) => (
                      <span
                        className="incident-chip"
                        key={`${alert.id}-mitre-${item}`}
                      >
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