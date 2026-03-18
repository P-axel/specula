import { useEffect, useMemo, useState } from "react";
import {
  fetchNetworkAlerts,
  fetchNetworkIncidents,
  fetchNetworkTheme,
} from "../../../api/network.api";

import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import RecentDetections from "../../dashboard/components/RecentDetections";
import "./NetworkPage.css";

function formatEndpoint(ip, port) {
  if (!ip) return "-";
  if (port === undefined || port === null || port === "") return String(ip);
  if (String(ip).includes(":")) return `[${ip}]:${port}`;
  return `${ip}:${port}`;
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("fr-FR");
}

function formatTimeBucketLabel(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleTimeString("fr-FR", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatRenderableValue(value) {
  if (value === null || value === undefined || value === "") return "-";

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  if (Array.isArray(value)) {
    if (!value.length) return "-";
    return value.map((item) => formatRenderableValue(item)).join(" • ");
  }

  if (typeof value === "object") {
    if ("src_ip" in value || "dest_ip" in value) {
      const left = formatEndpoint(value.src_ip, value.src_port);
      const right = formatEndpoint(value.dest_ip, value.dest_port);
      return `${left} → ${right}`;
    }

    if ("ip" in value || "port" in value) {
      return formatEndpoint(value.ip, value.port);
    }

    return JSON.stringify(value);
  }

  return String(value);
}

function formatPairsList(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map((item) => formatRenderableValue(item)).filter(Boolean);
  }
  return [formatRenderableValue(value)];
}

function getPriorityLabel(value) {
  const normalized = String(value || "info").toLowerCase();

  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium")) return "medium";
  if (normalized.includes("low")) return "low";
  return "info";
}

function getHighestPriority(alerts, incidents) {
  const values = [
    ...alerts.map((item) =>
      String(item.priority || item.risk_level || item.severity || "").toLowerCase()
    ),
    ...incidents.map((item) =>
      String(item.priority || item.risk_level || item.severity || "").toLowerCase()
    ),
  ];

  if (values.some((v) => v.includes("critical"))) return "critical";
  if (values.some((v) => v.includes("high"))) return "high";
  if (values.some((v) => v.includes("medium"))) return "medium";
  if (values.some((v) => v.includes("low"))) return "low";
  return "info";
}

function getSummaryTone(priority) {
  if (priority === "critical" || priority === "high") return "danger";
  if (priority === "medium") return "warning";
  return "info";
}

function groupCounts(items, extractor, limit = 5) {
  const map = new Map();

  items.forEach((item) => {
    const value = extractor(item);
    if (!value || value === "-") return;
    map.set(value, (map.get(value) || 0) + 1);
  });

  return Array.from(map.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function buildTimeline(alerts) {
  const map = new Map();

  alerts.forEach((item) => {
    const raw = item.created_at || item.timestamp || item.last_seen;
    if (!raw) return;

    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) return;

    date.setSeconds(0, 0);
    const key = date.toISOString();

    map.set(key, (map.get(key) || 0) + 1);
  });

  return Array.from(map.entries())
    .map(([bucket, count]) => ({
      bucket,
      label: formatTimeBucketLabel(bucket),
      count,
    }))
    .sort((a, b) => new Date(a.bucket) - new Date(b.bucket))
    .slice(-12);
}

function buildTopFlows(alerts, incidents) {
  const map = new Map();

  alerts.forEach((item) => {
    const src = item.src_label || formatEndpoint(item.src_ip, item.src_port);
    const dst = item.dest_label || formatEndpoint(item.dest_ip, item.dest_port);
    const proto = item.protocol_label || item.protocol || item.proto || "unknown";
    const key = `${src}|||${dst}|||${proto}`;
    const current = map.get(key) || {
      source: src,
      destination: dst,
      protocol: proto,
      count: 0,
      maxRisk: 0,
      priority: "info",
    };

    current.count += 1;
    current.maxRisk = Math.max(current.maxRisk, Number(item.risk_score || 0));
    current.priority = getPriorityLabel(item.priority || item.severity || current.priority);

    map.set(key, current);
  });

  incidents.forEach((item) => {
    const pairs = formatPairsList(item.ip_pairs || item.peer_ips);
    pairs.forEach((pair) => {
      const key = `${pair}|||incident|||corr`;
      const current = map.get(key) || {
        source: pair,
        destination: "",
        protocol: "corr",
        count: 0,
        maxRisk: 0,
        priority: "info",
      };

      current.count += 1;
      current.maxRisk = Math.max(current.maxRisk, Number(item.risk_score || 0));
      current.priority = getPriorityLabel(item.priority || item.severity || current.priority);

      map.set(key, current);
    });
  });

  return Array.from(map.values())
    .sort((a, b) => b.count - a.count || b.maxRisk - a.maxRisk)
    .slice(0, 8);
}

function buildProtocolDistribution(alerts) {
  const grouped = groupCounts(
    alerts,
    (item) => item.protocol_label || item.protocol || item.proto || "unknown",
    6
  );

  const total = grouped.reduce((sum, item) => sum + item.count, 0);

  return grouped.map((item) => ({
    ...item,
    percent: total ? Math.round((item.count / total) * 100) : 0,
  }));
}

function DetailRow({ label, value }) {
  return (
    <div className="network-detail-row">
      <div className="network-detail-label">{label}</div>
      <div className="network-detail-value">{formatRenderableValue(value)}</div>
    </div>
  );
}

function PriorityBadge({ value }) {
  const label = getPriorityLabel(value);
  return <span className={`network-badge network-badge--${label}`}>{label}</span>;
}

function MiniBarChart({ items }) {
  const max = Math.max(1, ...items.map((item) => item.count || 0));

  if (!items.length) {
    return <p className="network-empty">Aucune activité temporelle disponible.</p>;
  }

  return (
    <div className="network-mini-chart">
      {items.map((item) => (
        <div className="network-mini-chart__item" key={item.bucket}>
          <div
            className="network-mini-chart__bar"
            style={{ height: `${Math.max(10, (item.count / max) * 100)}%` }}
            title={`${item.label} · ${item.count}`}
          />
          <div className="network-mini-chart__value">{item.count}</div>
          <div className="network-mini-chart__label">{item.label}</div>
        </div>
      ))}
    </div>
  );
}

function TopList({ title, items }) {
  const max = Math.max(1, ...items.map((item) => item.count || 0));

  return (
    <div className="network-visual-card">
      <div className="network-visual-card__title">{title}</div>

      {!items.length ? (
        <p className="network-empty">Aucune donnée.</p>
      ) : (
        <div className="network-ranked-list">
          {items.map((item, index) => (
            <div className="network-ranked-item" key={`${title}-${item.label}-${index}`}>
              <div className="network-ranked-item__top">
                <span className="network-ranked-item__label">{item.label}</span>
                <span className="network-ranked-item__count">{item.count}</span>
              </div>
              <div className="network-ranked-item__track">
                <div
                  className="network-ranked-item__fill"
                  style={{ width: `${(item.count / max) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FlowsPanel({ items }) {
  return (
    <div className="network-visual-card">
      <div className="network-visual-card__title">Flux dominants</div>

      {!items.length ? (
        <p className="network-empty">Aucun flux dominant disponible.</p>
      ) : (
        <div className="network-flow-list">
          {items.map((item, index) => (
            <div className="network-flow-card" key={`flow-${index}`}>
              <div className="network-flow-card__top">
                <div className="network-flow-card__path">
                  <span className="network-flow-card__endpoint">{item.source}</span>
                  {item.destination ? (
                    <>
                      <span className="network-flow-card__arrow">→</span>
                      <span className="network-flow-card__endpoint">{item.destination}</span>
                    </>
                  ) : null}
                </div>

                <div className="network-flow-card__badges">
                  <PriorityBadge value={item.priority} />
                  <span className="network-mini-metric">{item.count} occ.</span>
                </div>
              </div>

              <div className="network-flow-card__meta">
                <span>Proto : {item.protocol}</span>
                <span>Score max : {item.maxRisk}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ProtocolsPanel({ items }) {
  return (
    <div className="network-visual-card">
      <div className="network-visual-card__title">Protocoles</div>

      {!items.length ? (
        <p className="network-empty">Aucune répartition disponible.</p>
      ) : (
        <div className="network-protocol-list">
          {items.map((item, index) => (
            <div className="network-protocol-item" key={`proto-${item.label}-${index}`}>
              <div className="network-protocol-item__top">
                <span className="network-protocol-item__label">{item.label}</span>
                <span className="network-protocol-item__meta">
                  {item.count} · {item.percent}%
                </span>
              </div>
              <div className="network-protocol-item__track">
                <div
                  className="network-protocol-item__fill"
                  style={{ width: `${item.percent}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function InvestigationPanel({ selectedAlert, selectedIncident, viewMode }) {
  if (viewMode === "alerts" && !selectedAlert) {
    return (
      <div className="network-panel-empty">
        <p className="network-empty">
          Sélectionne une alerte pour afficher les détails d’investigation.
        </p>
      </div>
    );
  }

  if (viewMode === "incidents" && !selectedIncident) {
    return (
      <div className="network-panel-empty">
        <p className="network-empty">
          Sélectionne un incident pour afficher les détails d’investigation.
        </p>
      </div>
    );
  }

  if (viewMode === "alerts" && selectedAlert) {
    return (
      <div className="network-detail-panel">
        <div className="network-detail-header">
          <div className="network-detail-kicker">Alerte réseau</div>
          <h3>{selectedAlert.title || "-"}</h3>
        </div>

        <p className="network-detail-description">
          {formatRenderableValue(
            selectedAlert.description || selectedAlert.summary || "-"
          )}
        </p>

        <div className="network-detail-grid">
          <DetailRow label="Priorité" value={selectedAlert.priority || selectedAlert.severity} />
          <DetailRow label="Score" value={selectedAlert.risk_score} />
          <DetailRow label="Confiance" value={selectedAlert.confidence} />
          <DetailRow label="Catégorie" value={selectedAlert.category} />
          <DetailRow label="Moteur" value={selectedAlert.source_engine || selectedAlert.engine} />
          <DetailRow
            label="Source"
            value={
              selectedAlert.src_label || {
                ip: selectedAlert.src_ip,
                port: selectedAlert.src_port,
              }
            }
          />
          <DetailRow
            label="Destination"
            value={
              selectedAlert.dest_label || {
                ip: selectedAlert.dest_ip,
                port: selectedAlert.dest_port,
              }
            }
          />
          <DetailRow
            label="Protocole"
            value={
              selectedAlert.protocol_label ||
              selectedAlert.protocol ||
              selectedAlert.proto
            }
          />
          <DetailRow label="Flow ID" value={selectedAlert.flow_id} />
          <DetailRow label="Règle" value={selectedAlert.rule_id} />
          <DetailRow label="Statut" value={selectedAlert.status} />
          <DetailRow label="Actif" value={selectedAlert.asset_name} />
        </div>
      </div>
    );
  }

  const pairs = formatPairsList(selectedIncident?.ip_pairs || selectedIncident?.peer_ips);

  return (
    <div className="network-detail-panel">
      <div className="network-detail-header">
        <div className="network-detail-kicker">Incident réseau</div>
        <h3>{selectedIncident?.title || "-"}</h3>
      </div>

      <p className="network-detail-description">
        {formatRenderableValue(selectedIncident?.description || "-")}
      </p>

      <div className="network-detail-grid">
        <DetailRow label="Priorité" value={selectedIncident?.priority || selectedIncident?.severity} />
        <DetailRow label="Score" value={selectedIncident?.risk_score} />
        <DetailRow label="Actif" value={selectedIncident?.asset_name} />
        <DetailRow label="Premier vu" value={selectedIncident?.first_seen} />
        <DetailRow label="Dernier vu" value={selectedIncident?.last_seen} />
        <DetailRow
          label="Détections"
          value={selectedIncident?.detections_count ?? selectedIncident?.signals_count ?? 0}
        />
        <DetailRow
          label="Moteurs"
          value={selectedIncident?.engines || selectedIncident?.source_engines}
        />
        <DetailRow label="Statut" value={selectedIncident?.status} />
      </div>

      <div className="network-detail-block">
        <h4>Pairs IP</h4>
        {pairs.length ? (
          <div className="network-chip-list">
            {pairs.map((pair, index) => (
              <span className="network-chip" key={`selected-pair-${index}`}>
                {pair}
              </span>
            ))}
          </div>
        ) : (
          <p className="network-empty">Aucune paire IP disponible.</p>
        )}
      </div>
    </div>
  );
}

export default function NetworkPage() {
  const [viewMode, setViewMode] = useState("alerts");
  const [themeData, setThemeData] = useState([]);
  const [alertsData, setAlertsData] = useState([]);
  const [incidentsData, setIncidentsData] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showInvestigation, setShowInvestigation] = useState(false);

  useEffect(() => {
    async function loadItems() {
      setLoading(true);
      setError("");

      try {
        const [themeResponse, alertsResponse, incidentsResponse] = await Promise.all([
          fetchNetworkTheme(20),
          fetchNetworkAlerts(100),
          fetchNetworkIncidents(100),
        ]);

        const nextTheme = Array.isArray(themeResponse?.items) ? themeResponse.items : [];
        const nextAlerts = Array.isArray(alertsResponse?.items) ? alertsResponse.items : [];
        const nextIncidents = Array.isArray(incidentsResponse?.items)
          ? incidentsResponse.items
          : [];

        setThemeData(nextTheme);
        setAlertsData(nextAlerts);
        setIncidentsData(nextIncidents);

        setSelectedAlert(nextAlerts[0] || null);
        setSelectedIncident(nextIncidents[0] || null);
      } catch (err) {
        setError(err.message || "Failed to load network data.");
        setThemeData([]);
        setAlertsData([]);
        setIncidentsData([]);
        setSelectedAlert(null);
        setSelectedIncident(null);
      } finally {
        setLoading(false);
      }
    }

    loadItems();
  }, []);

  const context = useMemo(() => {
    const maxRisk = Math.max(
      0,
      ...alertsData.map((item) => Number(item.risk_score || 0)),
      ...incidentsData.map((item) => Number(item.risk_score || 0))
    );

    const suspiciousSources = new Set(
      alertsData.map((item) => item.src_ip).filter(Boolean)
    ).size;

    const targetedAssets = new Set(
      [
        ...alertsData.map((item) => item.asset_name || item.dest_ip),
        ...incidentsData.map((item) => item.asset_name),
      ].filter(Boolean)
    ).size;

    const highestPriority = getHighestPriority(alertsData, incidentsData);

    return {
      highestPriority,
      maxRisk,
      suspiciousSources,
      targetedAssets,
    };
  }, [alertsData, incidentsData]);

  const cards = useMemo(() => {
    const currentItems = viewMode === "alerts" ? alertsData : incidentsData;
    const highCount = currentItems.filter((item) => {
      const severity = String(item.priority || item.risk_level || item.severity || "").toLowerCase();
      return severity.includes("high") || severity.includes("critical");
    }).length;

    const lowInfoCount = currentItems.filter((item) => {
      const severity = String(item.priority || item.risk_level || item.severity || "").toLowerCase();
      return severity.includes("low") || severity.includes("info");
    }).length;

    return [
      {
        label: "Détections réseau",
        value: themeData.length,
        tone: "info",
      },
      {
        label: viewMode === "alerts" ? "Alertes réseau" : "Incidents réseau",
        value: currentItems.length,
        tone: "warning",
      },
      {
        label: "High Severity",
        value: highCount,
        tone: "danger",
      },
      {
        label: viewMode === "alerts" ? "Low / Informational" : "Priorité max",
        value: viewMode === "alerts" ? lowInfoCount : context.highestPriority,
        tone: viewMode === "alerts" ? "success" : getSummaryTone(context.highestPriority),
      },
    ];
  }, [alertsData, incidentsData, themeData, viewMode, context.highestPriority]);

  const pageTitle = viewMode === "alerts" ? "Network Alerts" : "Network Incidents";

  const pageDescription =
    viewMode === "alerts"
      ? "Alertes Suricata présentées dans un format de lecture rapide orienté triage et qualification."
      : "Incidents réseau corrélés par Specula à partir de plusieurs alertes cohérentes et priorisées.";

  const badgeText =
    viewMode === "alerts"
      ? `${alertsData.length} alertes`
      : `${incidentsData.length} incidents`;

  const normalizedItems = useMemo(() => {
    if (viewMode === "alerts") {
      return alertsData.map((alert) => ({
        id: alert.id,
        title: alert.title || alert.signature || alert.summary || "Network alert",
        name: alert.title || alert.signature || "Network alert",
        description:
          alert.description ||
          `${alert.src_label || formatEndpoint(alert.src_ip, alert.src_port)} → ${
            alert.dest_label || formatEndpoint(alert.dest_ip, alert.dest_port)
          }`,
        severity: alert.priority || alert.severity || "info",
        risk_score: alert.risk_score,
        risk_level: alert.risk_level,
        source: alert.source_engine || alert.engine || "suricata",
        asset_id: alert.asset_id,
        asset_name: alert.asset_name || alert.dest_ip,
        hostname: alert.hostname,
        timestamp: alert.created_at || alert.timestamp,
        created_at: alert.created_at || alert.timestamp,
        updated_at: alert.updated_at,
        category: alert.category || "network_alert",
        type: "alert",
        status: alert.status || "open",
        signals_count: 1,
        metadata: {
          protocol: alert.protocol_label || alert.protocol || alert.proto,
          src_label: alert.src_label || formatEndpoint(alert.src_ip, alert.src_port),
          dest_label: alert.dest_label || formatEndpoint(alert.dest_ip, alert.dest_port),
          flow_id: alert.flow_id,
          rule_id: alert.rule_id,
        },
      }));
    }

    return incidentsData.map((incident) => ({
      id: incident.id,
      title: incident.title,
      name: incident.name || incident.title,
      description: incident.description,
      severity: incident.severity,
      risk_score: incident.risk_score,
      risk_level: incident.risk_level,
      source: incident.source || "specula",
      asset_id: incident.asset_id,
      asset_name: incident.asset_name,
      hostname: incident.hostname,
      timestamp: incident.updated_at || incident.created_at || incident.timestamp,
      created_at: incident.created_at || incident.timestamp,
      updated_at: incident.updated_at,
      category: incident.category || "network_incident",
      type: incident.type || "incident",
      status: incident.status || "open",
      signals_count: incident.signals_count || incident.detections_count || 0,
      metadata: {
        ...(incident.metadata || {}),
        signals: incident.signals || [],
        pairs: incident.ip_pairs || incident.peer_ips || [],
        engines: incident.engines || [],
      },
    }));
  }, [alertsData, incidentsData, viewMode]);

  const timeline = useMemo(() => buildTimeline(alertsData), [alertsData]);
  const topSources = useMemo(
    () => groupCounts(alertsData, (item) => item.src_ip || item.src_label, 5),
    [alertsData]
  );
  const topDestinations = useMemo(
    () => groupCounts(alertsData, (item) => item.dest_ip || item.dest_label, 5),
    [alertsData]
  );
  const topFlows = useMemo(
    () => buildTopFlows(alertsData, incidentsData),
    [alertsData, incidentsData]
  );
  const protocolDistribution = useMemo(
    () => buildProtocolDistribution(alertsData),
    [alertsData]
  );

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Network"
        title={pageTitle}
        description={pageDescription}
        badge={badgeText}
      />

      <div
        style={{
          display: "flex",
          gap: "0.75rem",
          marginBottom: "1rem",
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <button
          type="button"
          onClick={() => setViewMode("alerts")}
          className={viewMode === "alerts" ? "btn btn-primary" : "btn btn-secondary"}
        >
          Alertes
        </button>

        <button
          type="button"
          onClick={() => setViewMode("incidents")}
          className={viewMode === "incidents" ? "btn btn-primary" : "btn btn-secondary"}
        >
          Incidents
        </button>

        <span style={{ opacity: 0.75, fontSize: "0.95rem" }}>
          {loading
            ? "Chargement..."
            : viewMode === "alerts"
            ? `${alertsData.length} alerte(s)`
            : `${incidentsData.length} incident(s)`}
        </span>
      </div>

      <MetricCards items={cards} />

      {error ? (
        <PageSection title="Erreur">
          <p className="error-text">{error}</p>
        </PageSection>
      ) : (
        <>
          <PageSection>
            {loading ? (
              <p>Chargement des données réseau...</p>
            ) : (
              <RecentDetections detections={normalizedItems} />
            )}
          </PageSection>

          <div
            style={{
              display: "flex",
              gap: "0.75rem",
              marginBottom: "1rem",
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <button
              type="button"
              onClick={() => setShowInvestigation((value) => !value)}
              className={showInvestigation ? "btn btn-primary" : "btn btn-secondary"}
            >
              {showInvestigation ? "Masquer l’investigation" : "Afficher l’investigation"}
            </button>

            <button
              type="button"
              onClick={() => setShowAdvanced((value) => !value)}
              className={showAdvanced ? "btn btn-primary" : "btn btn-secondary"}
            >
              {showAdvanced ? "Masquer l’analyse avancée" : "Afficher l’analyse avancée"}
            </button>
          </div>

          {showInvestigation ? (
            <PageSection title="Panneau d’investigation">
              <InvestigationPanel
                selectedAlert={selectedAlert}
                selectedIncident={selectedIncident}
                viewMode={viewMode}
              />
            </PageSection>
          ) : null}

          {showAdvanced ? (
            <>
              <div className="network-visual-layout">
                <PageSection title="Activité réseau">
                  <MiniBarChart items={timeline} />
                </PageSection>

                <PageSection title="Top talkers">
                  <div className="network-visual-stack">
                    <TopList title="Top sources" items={topSources} />
                    <TopList title="Top destinations" items={topDestinations} />
                  </div>
                </PageSection>
              </div>

              <div className="network-visual-layout">
                <PageSection title="Analyse réseau avancée">
                  <FlowsPanel items={topFlows} />
                </PageSection>

                <PageSection title="Répartition">
                  <ProtocolsPanel items={protocolDistribution} />
                </PageSection>
              </div>
            </>
          ) : null}
        </>
      )}
    </div>
  );
}