import { useMemo } from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  BarChart,
  Bar,
  Cell,
} from "recharts";

import { useSocData } from "../../../shared/providers/SocDataProvider";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import RecentDetections from "../../../shared/ui/RecentDetections";

import "./DashboardPage.css";

const SEVERITY_COLORS = ["#ff6f6f", "#ffb07b", "#ffd47c", "#9fd0ff", "#89e6cb"];

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
    <div
      style={{
        padding: "18px",
        borderRadius: "16px",
        background:
          "linear-gradient(180deg, rgba(18, 31, 56, 0.96), rgba(12, 23, 43, 0.96))",
        border: "1px solid rgba(120, 162, 255, 0.18)",
        boxShadow: "0 12px 28px rgba(0, 0, 0, 0.18)",
      }}
    >
      <div
        style={{
          fontSize: "0.92rem",
          color: "rgba(196, 210, 230, 0.78)",
          marginBottom: "10px",
        }}
      >
        {title}
      </div>

      <div
        style={{
          fontSize: "2rem",
          fontWeight: 700,
          color: "#eaf2ff",
        }}
      >
        {value}
      </div>

      {hint ? (
        <div
          style={{
            marginTop: "8px",
            fontSize: "0.85rem",
            color: "rgba(196, 210, 230, 0.64)",
            lineHeight: 1.4,
          }}
        >
          {hint}
        </div>
      ) : null}
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

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "16px",
            marginTop: "16px",
          }}
        >
          <StatCard
            title="Incidents connus"
            value={localStats.incidentsCount}
            hint="Volume total d’incidents actuellement visibles dans Specula."
          />
          <StatCard
            title="Incidents high/critical"
            value={localStats.highIncidents}
            hint="Incidents les plus prioritaires pour l’investigation."
          />
          <StatCard
            title="Conversion en incidents"
            value={`${localStats.incidentConversionRate}%`}
            hint="Part des détections SOC qui aboutissent à un incident visible."
          />
          <StatCard
            title="Corrélation réseau"
            value={`${localStats.networkCorrelationRate}%`}
            hint="Part des détections réseau qualifiées en corrélations réseau."
          />
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
                    <CartesianGrid strokeDasharray="3 3" stroke="#223250" />
                    <XAxis dataKey="time" stroke="#93a8c8" />
                    <YAxis stroke="#93a8c8" />
                    <Tooltip />
                    <Line type="monotone" dataKey="count" stroke="#7db3ff" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </PageSection>

            <PageSection title="Niveau de sévérité observé">
              <div className="dashboard-chart-shell">
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name" outerRadius={95}>
                      {severityData.map((entry, index) => (
                        <Cell
                          key={`severity-${entry.name}-${index}`}
                          fill={SEVERITY_COLORS[index % SEVERITY_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip />
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
                  <BarChart data={topAssets}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#223250" />
                    <XAxis dataKey="name" stroke="#93a8c8" />
                    <YAxis stroke="#93a8c8" />
                    <Tooltip />
                    <Bar dataKey="count" fill="#7db3ff" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </PageSection>

            <PageSection title="Catégories dominantes">
              <div className="dashboard-chart-shell">
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={topCategories}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#223250" />
                    <XAxis dataKey="name" stroke="#93a8c8" />
                    <YAxis stroke="#93a8c8" />
                    <Tooltip />
                    <Bar dataKey="count" fill="#89e6cb" radius={[6, 6, 0, 0]} />
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