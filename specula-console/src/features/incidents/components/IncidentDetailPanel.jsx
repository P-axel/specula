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

function DetailTagList({ title, items, emptyLabel }) {
  return (
    <div className="incident-detail-block">
      <h4>{title}</h4>
      {items?.length ? (
        <div className="incident-chip-list">
          {items.map((item, index) => (
            <span className="incident-chip" key={`${title}-${index}-${item}`}>
              {item}
            </span>
          ))}
        </div>
      ) : (
        <p className="empty-state">{emptyLabel}</p>
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

  return (
    <div className="incident-detail-panel">
      <div className="incident-detail-header">
        <div className="incident-detail-kicker">Incident</div>
        <h3>{incident.title || "-"}</h3>
      </div>

      <div className="incident-chip-list" style={{ marginBottom: 16 }}>
        <PriorityBadge value={incident.severity} />
        <IncidentKindBadge kind={incident.kind} />
        <IncidentEngineBadge engine={incident.engine} />
      </div>

      <p className="incident-detail-description">
        {formatRenderableValue(incident.description || "-")}
      </p>

      <div className="incident-detail-grid">
        <DetailRow label="Famille" value={KIND_LABELS[incident.kind] || "Autre"} />
        <DetailRow
          label="Moteur de détection"
          value={
            incident.engine === "non précisé"
              ? "Moteur non identifié"
              : incident.engine
          }
        />
        <DetailRow label="Sévérité" value={incident.severity} />
        <DetailRow label="Score" value={incident.risk_score} />
        <DetailRow label="Actif" value={incident.asset_name} />
        <DetailRow label="Catégorie" value={incident.category} />
        <DetailRow label="Type" value={incident.event_type} />
        <DetailRow label="Statut" value={incident.status} />
        <DetailRow label="Agent" value={incident.agent_name} />
        <DetailRow label="Agent ID" value={incident.agent_id} />
        <DetailRow label="Premier vu" value={formatDateTime(incident.first_seen)} />
        <DetailRow label="Dernier vu" value={formatDateTime(incident.last_seen)} />
        <DetailRow label="Détections" value={incident.detections_count ?? 0} />
      </div>

      {incident.kind === "network" && (
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
      )}

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
        items={incident.cves}
        emptyLabel="Aucun CVE associé."
      />

      <DetailTagList
        title="MITRE / ATT&CK"
        items={incident.mitre}
        emptyLabel="Aucune référence MITRE disponible."
      />

      <DetailTagList
        title="Utilisateurs impliqués"
        items={incident.users}
        emptyLabel="Aucun utilisateur identifié."
      />

      <DetailTagList
        title="Processus observés"
        items={incident.processes}
        emptyLabel="Aucun processus remonté."
      />

      <DetailTagList
        title="Fichiers / chemins"
        items={incident.files}
        emptyLabel="Aucun fichier remonté."
      />

      <DetailTagList
        title="Clés registre"
        items={incident.registry_keys}
        emptyLabel="Aucune clé registre remontée."
      />

      <DetailTagList
        title="Éléments d'analyse"
        items={incident.evidence}
        emptyLabel="Aucun élément complémentaire."
      />

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