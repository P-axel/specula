import { useMemo } from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  BarChart,
  Bar,
  Cell,
} from "recharts";

const CHART_TOOLTIP_STYLE = {
  backgroundColor: "#082030",
  border: "1px solid #24607e",
  borderRadius: "6px",
  color: "#cce4f4",
  fontSize: "0.8rem",
};
const CHART_AXIS_STYLE = { fill: "#6899b4", fontSize: 11 };
const CHART_GRID_COLOR = "#183f58";

import { useSocData } from "../../../shared/providers/SocDataProvider";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import RecentDetections from "../../../shared/ui/RecentDetections";

import "./DashboardPage.css";

const SEVERITY_COLORS = ["#ff6f6f", "#ffb07b", "#ffd47c", "#9fd0ff", "#89e6cb"];

const SOURCES_META = {
  suricata: { label: "Suricata", subtitle: "IDS Réseau" },
  wazuh:    { label: "Wazuh",    subtitle: "SIEM / Endpoint" },
};

function formatRelative(isoStr) {
  if (!isoStr) return null;
  const diff = Date.now() - new Date(isoStr).getTime();
  if (isNaN(diff)) return null;
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "à l'instant";
  if (m < 60) return `il y a ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `il y a ${h} h`;
  return `il y a ${Math.floor(h / 24)} j`;
}

function SourceCard({ engineKey, count, lastSeen }) {
  const meta = SOURCES_META[engineKey] || { label: engineKey, subtitle: "" };
  const active = count > 0;
  return (
    <div className={`source-card source-card--${active ? "active" : "inactive"}`}>
      <div className="source-card__header">
        <span className="source-card__dot" />
        <div>
          <span className="source-card__name">{meta.label}</span>
          <span className="source-card__subtitle">{meta.subtitle}</span>
        </div>
        <span className="source-card__badge">{active ? "Actif" : "Inactif"}</span>
      </div>
      <div className="source-card__count">{count}</div>
      <div className="source-card__hint">
        {active ? `détection${count > 1 ? "s" : ""} remontée${count > 1 ? "s" : ""}` : "aucune détection"}
      </div>
      {lastSeen && (
        <div className="source-card__last-seen">Dernier signal : {formatRelative(lastSeen)}</div>
      )}
    </div>
  );
}

function getPriorityLabel(value) {
  const normalized = String(value || "info").toLowerCase();

  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium")) return "medium";
  if (normalized.includes("low")) return "low";
  return "info";
}

function isOpenIncidentStatus(value) {
  const status = String(value || "open").toLowerCase();
  return status === "open" || status === "investigating";
}

function OverviewCard({ tone = "info", label, value, hint }) {
  return (
    <article className={`dashboard-overview-card dashboard-overview-card--${tone}`}>
      <span className="dashboard-overview-card__label">{label}</span>
      <strong className="dashboard-overview-card__value">{value}</strong>
      <p className="dashboard-overview-card__hint">{hint}</p>
    </article>
  );
}

function StatCard({ title, value, hint }) {
  return (
    <div className="dashboard-stat-card">
      <div className="dashboard-stat-card__label">{title}</div>
      <div className="dashboard-stat-card__value">{value}</div>
      {hint ? <div className="dashboard-stat-card__hint">{hint}</div> : null}
    </div>
  );
}

export default function DashboardPage() {
  const {
    incidentsRaw,
    alertsRaw,
    overview,
    severity,
    activity,
    topAssets,
    topCategories,
    detections,
    refreshing,
    refreshSocData,
    error,
  } = useSocData();

  const localStats = useMemo(() => {
    const normalizedIncidents = incidentsRaw.map((incident) => ({
      severity: getPriorityLabel(incident?.severity || incident?.priority),
      status: String(incident?.status || "open").toLowerCase(),
      first_seen: incident?.first_seen || incident?.timestamp,
      engines: incident?.engines || [],
    }));

    const incidentsCount = normalizedIncidents.length;
    const alertsCount = alertsRaw.length;

    const criticalIncidents = normalizedIncidents.filter(
      (incident) => incident.severity === "critical"
    ).length;

    const highIncidents = normalizedIncidents.filter(
      (incident) => incident.severity === "high" || incident.severity === "critical"
    ).length;

    const openIncidents = normalizedIncidents.filter((incident) =>
      isOpenIncidentStatus(incident.status)
    ).length;

    const investigatingIncidents = normalizedIncidents.filter(
      (i) => i.status === "investigating"
    ).length;

    const resolvedIncidents = normalizedIncidents.filter(
      (i) => i.status === "resolved" || i.status === "false_positive"
    ).length;

    // Dwell time : âge du plus vieil incident ouvert critique/high
    const openCriticalHigh = incidentsRaw.filter(
      (i) =>
        isOpenIncidentStatus(String(i?.status || "open").toLowerCase()) &&
        (getPriorityLabel(i?.severity || i?.priority) === "critical" ||
          getPriorityLabel(i?.severity || i?.priority) === "high")
    );
    let oldestCriticalMs = 0;
    for (const i of openCriticalHigh) {
      const ts = i.first_seen || i.timestamp;
      if (ts) {
        const age = Date.now() - new Date(ts).getTime();
        if (age > oldestCriticalMs) oldestCriticalMs = age;
      }
    }
    const oldestCriticalAge = oldestCriticalMs > 0 ? formatRelative(new Date(Date.now() - oldestCriticalMs).toISOString()) : null;

    // Breakdown par moteur
    const suricataCount = incidentsRaw.filter(
      (i) => (i.engines || []).includes("suricata") || i.engine === "suricata"
    ).length;
    const wazuhCount = incidentsRaw.filter(
      (i) => (i.engines || []).includes("wazuh") || i.engine === "wazuh"
    ).length;

    const assetsTotal = overview?.assets?.total || 0;
    const assetsActive = overview?.assets?.active || 0;

    const activeCoverage = assetsTotal
      ? Math.round((assetsActive / assetsTotal) * 100)
      : 0;

    const socDetections = overview?.soc?.detections_total || 0;
    const socEvents = overview?.soc?.events_total || 0;

    const networkDetections = overview?.network?.detections_total || 0;
    const networkSignals = overview?.network?.alerts_total || 0;
    const networkCorrelations = overview?.network?.incidents_total || 0;

    const incidentConversionRate = socDetections
      ? Math.round((incidentsCount / socDetections) * 100)
      : 0;

    const networkCorrelationRate = networkDetections
      ? Math.round((networkCorrelations / networkDetections) * 100)
      : 0;

    return {
      incidentsCount,
      alertsCount,
      criticalIncidents,
      highIncidents,
      openIncidents,
      investigatingIncidents,
      resolvedIncidents,
      oldestCriticalAge,
      suricataCount,
      wazuhCount,
      activeCoverage,
      socDetections,
      socEvents,
      networkDetections,
      networkSignals,
      networkCorrelations,
      incidentConversionRate,
      networkCorrelationRate,
    };
  }, [incidentsRaw, alertsRaw, overview]);

  const sourcesStatus = useMemo(() => {
    const acc = {};
    for (const engineKey of Object.keys(SOURCES_META)) {
      acc[engineKey] = { count: 0, lastSeen: null };
    }
    for (const d of detections) {
      const engine = String(d.engine || d.source || "").toLowerCase();
      if (engine in acc) {
        acc[engine].count++;
        const ts = d.timestamp || d.created_at;
        if (ts && (!acc[engine].lastSeen || ts > acc[engine].lastSeen)) {
          acc[engine].lastSeen = ts;
        }
      }
    }
    return Object.entries(acc).map(([key, val]) => ({ engineKey: key, ...val }));
  }, [detections]);

  const headlineCards = useMemo(() => {
    if (!overview) return [];

    return [
      {
        label: "Actifs surveillés",
        value: overview?.assets?.total || 0,
        tone: "primary",
      },
      {
        label: "Couverture active",
        value: `${localStats.activeCoverage}%`,
        tone: "success",
      },
      {
        label: "Incidents à traiter",
        value: localStats.openIncidents,
        tone: "warning",
      },
      {
        label: "Incidents critiques",
        value: localStats.criticalIncidents,
        tone: "danger",
      },
    ];
  }, [overview, localStats]);

  const severityData = useMemo(() => {
    if (!severity) return [];

    return [
      { name: "Critical", value: severity.critical || 0 },
      { name: "High", value: severity.high || 0 },
      { name: "Medium", value: severity.medium || 0 },
      { name: "Low", value: severity.low || 0 },
      { name: "Info", value: severity.info || 0 },
    ];
  }, [severity]);

  const heroBadge = useMemo(() => {
    if (!overview) return "Aucune donnée";
    return `${overview?.assets?.active || 0}/${overview?.assets?.total || 0} actifs remontent · ${localStats.incidentsCount} incident(s) visibles`;
  }, [overview, localStats]);

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Security Operations"
        title="État de sécurité du SI"
        description="Vue claire de la couverture, de l’activité observée et des incidents réellement utiles à traiter."
        badge={heroBadge}
      />

      <PageSection title="Synthèse opérationnelle">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: "16px",
            marginBottom: "24px",
            flexWrap: "wrap",
          }}
        >
          <p style={{ margin: 0, opacity: 0.78 }}>
            Lecture orientée pilotage, exposition et priorisation.
          </p>

          <button
            onClick={refreshSocData}
            disabled={refreshing}
            style={{
              border: "none",
              borderRadius: "10px",
              padding: "10px 16px",
              cursor: refreshing ? "not-allowed" : "pointer",
              background: "#2160ff",
              color: "#fff",
              fontWeight: 600,
              opacity: refreshing ? 0.72 : 1,
            }}
          >
            {refreshing ? "Actualisation..." : "Rafraîchir"}
          </button>
        </div>

        <MetricCards items={headlineCards} />

        <div className="dashboard-overview-grid" style={{ marginTop: "12px" }}>
          <StatCard
            title="Incidents high/critical"
            value={localStats.highIncidents}
            hint="Incidents prioritaires à traiter en premier."
          />
          <StatCard
            title="En investigation"
            value={localStats.investigatingIncidents}
            hint="Incidents pris en charge par un analyste."
          />
          <StatCard
            title="Résolus / FP"
            value={localStats.resolvedIncidents}
            hint="Incidents fermés (résolus + faux positifs)."
          />
          <StatCard
            title="Dwell time critique"
            value={localStats.oldestCriticalAge || "—"}
            hint={localStats.oldestCriticalAge
              ? "Âge du plus vieil incident critique/high ouvert non traité."
              : "Aucun incident critique ouvert."}
          />
          <StatCard
            title="Incidents Suricata"
            value={localStats.suricataCount}
            hint="Incidents provenant du moteur réseau Suricata."
          />
          <StatCard
            title="Incidents Wazuh"
            value={localStats.wazuhCount}
            hint="Incidents provenant du moteur endpoint Wazuh."
          />
        </div>
      </PageSection>

      <PageSection title="Sources actives">
        <div className="sources-grid">
          {sourcesStatus.map((src) => (
            <SourceCard key={src.engineKey} {...src} />
          ))}
        </div>
      </PageSection>

      {error ? (
        <PageSection title="Dashboard">
          <p className="error-text">{error}</p>
        </PageSection>
      ) : (
        <>
          <div className="dashboard-layout-two-columns">
            <PageSection title="Activité récente">
              <div className="dashboard-chart-shell">
                <ResponsiveContainer width="100%" height={280}>
                  <LineChart data={activity}>
                    <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID_COLOR} />
                    <XAxis dataKey="time" tick={CHART_AXIS_STYLE} axisLine={{ stroke: CHART_GRID_COLOR }} tickLine={false} />
                    <YAxis tick={CHART_AXIS_STYLE} axisLine={{ stroke: CHART_GRID_COLOR }} tickLine={false} />
                    <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                    <Line type="monotone" dataKey="count" stroke="#00e5ff" strokeWidth={2} dot={false} activeDot={{ r: 4, fill: "#00e5ff" }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </PageSection>

            <PageSection title="Répartition par sévérité">
              <div className="dashboard-chart-shell">
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie
                      data={severityData.filter(d => d.value > 0)}
                      dataKey="value"
                      nameKey="name"
                      outerRadius={95}
                      innerRadius={45}
                      paddingAngle={3}
                    >
                      {severityData.filter(d => d.value > 0).map((entry, index) => (
                        <Cell
                          key={`severity-${entry.name}-${index}`}
                          fill={SEVERITY_COLORS[index % SEVERITY_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                    <Legend
                      formatter={(value) => <span style={{ color: "#cce4f4", fontSize: "0.78rem" }}>{value}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </PageSection>
          </div>

          <PageSection title="État du parc">
            <div className="dashboard-layout-two-columns">
              <section className="dashboard-panel">
                <div className="dashboard-panel__header">
                  <h3 className="dashboard-panel__title">Postes et couverture</h3>
                </div>

                <div className="dashboard-overview-grid">
                  <OverviewCard
                    tone="info"
                    label="Actifs surveillés"
                    value={overview?.assets?.total || 0}
                    hint="Nombre total de postes et actifs remontés dans la plateforme."
                  />
                  <OverviewCard
                    tone="info"
                    label="Actifs actifs"
                    value={overview?.assets?.active || 0}
                    hint="Actifs actuellement vus et remontant de la télémétrie."
                  />
                  <OverviewCard
                    tone="warning"
                    label="Actifs en vigilance"
                    value={overview?.assets?.warning || 0}
                    hint="Actifs présentant un état à surveiller."
                  />
                  <OverviewCard
                    tone="danger"
                    label="Actifs critiques"
                    value={overview?.assets?.critical || 0}
                    hint="Actifs les plus sensibles ou dégradés."
                  />
                </div>
              </section>

              <section className="dashboard-panel">
                <div className="dashboard-panel__header">
                  <h3 className="dashboard-panel__title">Risque et traitement</h3>
                </div>

                <div className="dashboard-overview-grid">
                  <OverviewCard
                    tone="warning"
                    label="Incidents ouverts"
                    value={localStats.openIncidents}
                    hint="Incidents qui demandent encore une analyse ou une action."
                  />
                  <OverviewCard
                    tone="danger"
                    label="Incidents critiques"
                    value={localStats.criticalIncidents}
                    hint="Incidents au plus haut niveau de priorité."
                  />
                  <OverviewCard
                    tone="info"
                    label="Alertes SOC"
                    value={localStats.alertsCount}
                    hint="Flux global d’alertes actuellement visible dans Specula."
                  />
                  <OverviewCard
                    tone="info"
                    label="Détections observées"
                    value={localStats.socDetections}
                    hint="Signaux observés servant à produire des incidents utiles."
                  />
                </div>
              </section>
            </div>
          </PageSection>

          <PageSection title="Lecture réseau">
            <div className="dashboard-layout-two-columns">
              <section className="dashboard-panel">
                <div className="dashboard-panel__header">
                  <h3 className="dashboard-panel__title">État du réseau</h3>
                </div>

                <div className="dashboard-overview-grid">
                  <OverviewCard
                    tone="info"
                    label="Activité réseau détectée"
                    value={localStats.networkDetections}
                    hint="Volume d’événements réseau détectés sur la période."
                  />
                  <OverviewCard
                    tone="warning"
                    label="Corrélations réseau"
                    value={localStats.networkCorrelations}
                    hint="Situations réseau corrélées par le pipeline dédié."
                  />
                  <OverviewCard
                    tone="info"
                    label="Signalements réseau"
                    value={localStats.networkSignals}
                    hint="Éléments qualifiés par le pipeline réseau."
                  />
                </div>
              </section>

              <section className="dashboard-panel">
                <div className="dashboard-panel__header">
                  <h3 className="dashboard-panel__title">Lecture globale</h3>
                </div>

                <div className="dashboard-overview-grid">
                  <OverviewCard
                    tone="info"
                    label="Événements collectés"
                    value={localStats.socEvents}
                    hint="Base de visibilité opérationnelle remontée dans Specula."
                  />
                  <OverviewCard
                    tone="info"
                    label="Détections analysées"
                    value={localStats.socDetections}
                    hint="Matière première utilisée pour qualifier et corréler."
                  />
                  <OverviewCard
                    tone="warning"
                    label="Incidents produits"
                    value={localStats.incidentsCount}
                    hint="Résultat final exploitable par l’analyste."
                  />
                </div>
              </section>
            </div>
          </PageSection>

          <div className="dashboard-layout-two-columns">
            <PageSection title="Actifs les plus exposés">
              <div className="dashboard-chart-shell">
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={topAssets} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID_COLOR} horizontal={false} />
                    <XAxis type="number" tick={CHART_AXIS_STYLE} axisLine={{ stroke: CHART_GRID_COLOR }} tickLine={false} />
                    <YAxis type="category" dataKey="name" tick={CHART_AXIS_STYLE} axisLine={false} tickLine={false} width={90} />
                    <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                    <Bar dataKey="count" fill="#00e5ff" radius={[0, 6, 6, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </PageSection>

            <PageSection title="Catégories dominantes">
              <div className="dashboard-chart-shell">
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={topCategories} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID_COLOR} horizontal={false} />
                    <XAxis type="number" tick={CHART_AXIS_STYLE} axisLine={{ stroke: CHART_GRID_COLOR }} tickLine={false} />
                    <YAxis type="category" dataKey="name" tick={CHART_AXIS_STYLE} axisLine={false} tickLine={false} width={110} />
                    <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                    <Bar dataKey="count" fill="#00ffcc" radius={[0, 6, 6, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </PageSection>
          </div>

          <PageSection title="Dernières détections">
            {!detections.length ? (
              <p className="empty-state">Aucune détection récente disponible.</p>
            ) : (
              <RecentDetections detections={detections.slice(0, 6)} />
            )}
          </PageSection>
        </>
      )}
    </div>
  );
}