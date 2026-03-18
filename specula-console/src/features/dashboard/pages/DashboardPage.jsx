import { useEffect, useMemo, useState } from "react";
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

import {
  getDashboardOverview,
  getSeverityDistribution,
  getDashboardActivity,
  getTopAssets,
  getTopCategories,
} from "../../../api/dashboard.api";

import { getDetections } from "../../../api/detections.api";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import RecentDetections from "../components/RecentDetections";
import "./DashboardPage.css";

function OverviewCard({ tone = "info", label, value, hint }) {
  return (
    <div className={`dashboard-network-card dashboard-network-card--${tone}`}>
      <div className="dashboard-network-card__label">{label}</div>
      <div className="dashboard-network-card__value">{value}</div>
      <div className="dashboard-network-card__hint">{hint}</div>
    </div>
  );
}

export default function DashboardPage() {
  const [overview, setOverview] = useState(null);
  const [severity, setSeverity] = useState(null);
  const [activity, setActivity] = useState([]);
  const [topAssets, setTopAssets] = useState([]);
  const [topCategories, setTopCategories] = useState([]);
  const [detections, setDetections] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadDashboard() {
      setLoading(true);
      setError("");

      try {
        const [
          overviewData,
          severityData,
          activityData,
          topAssetsData,
          topCategoriesData,
          detectionsData,
        ] = await Promise.all([
          getDashboardOverview(),
          getSeverityDistribution(),
          getDashboardActivity(),
          getTopAssets(),
          getTopCategories(),
          getDetections(),
        ]);

        setOverview(overviewData);
        setSeverity(severityData);
        setActivity(Array.isArray(activityData) ? activityData : []);
        setTopAssets(Array.isArray(topAssetsData) ? topAssetsData : []);
        setTopCategories(Array.isArray(topCategoriesData) ? topCategoriesData : []);
        setDetections(Array.isArray(detectionsData) ? detectionsData : []);
      } catch (err) {
        setError(err.message || "Failed to load dashboard.");
        setOverview(null);
        setSeverity(null);
        setActivity([]);
        setTopAssets([]);
        setTopCategories([]);
        setDetections([]);
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

  const cards = useMemo(() => {
    if (!overview) return [];

    return [
      { label: "Actifs", value: overview.assets_total || 0, tone: "primary" },
      { label: "Agents actifs", value: overview.assets_active || 0, tone: "success" },
      { label: "Actifs critiques", value: overview.assets_critical || 0, tone: "danger" },
      { label: "Alertes ouvertes", value: overview.alerts_open || 0, tone: "warning" },
      { label: "Signaux", value: overview.detections_total || 0, tone: "info" },
    ];
  }, [overview]);

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
    if (loading) return "Chargement...";
    if (!overview) return "Aucune donnée";

    return `${overview.assets_total || 0} actifs · ${overview.alerts_open || 0} alertes ouvertes`;
  }, [loading, overview]);

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Security Operations"
        title="Vue SOC"
        description="Vue synthétique, visuelle et exploitable des actifs, signaux et tendances de sécurité."
        badge={heroBadge}
      />

      {error ? (
        <PageSection title="Dashboard">
          <p className="error-text">{error}</p>
        </PageSection>
      ) : (
        <>
          <MetricCards items={cards} />

          <PageSection title="Couverture de détection">
            <div className="dashboard-grid-2">
              <div>
                <h3 style={{ marginTop: 0, marginBottom: "1rem" }}>Analyse générale</h3>
                <div className="dashboard-network-grid">
                  <OverviewCard
                    tone="info"
                    label="Signaux"
                    value={overview?.detections_total || 0}
                    hint="Éléments détectés et qualifiés par la plateforme"
                  />
                  <OverviewCard
                    tone="warning"
                    label="Alertes ouvertes"
                    value={overview?.alerts_open || 0}
                    hint="Éléments nécessitant encore une qualification"
                  />
                  <OverviewCard
                    tone="danger"
                    label="Alertes critiques"
                    value={overview?.alerts_critical || 0}
                    hint="Éléments au plus haut niveau de priorité"
                  />
                </div>
              </div>

              <div>
                <h3 style={{ marginTop: 0, marginBottom: "1rem" }}>Réseau</h3>
                <div className="dashboard-network-grid">
                  <OverviewCard
                    tone="info"
                    label="Détections réseau"
                    value={overview?.network_detections_total || 0}
                    hint="Signaux réseau identifiés et classés"
                  />
                  <OverviewCard
                    tone="warning"
                    label="Alertes réseau"
                    value={overview?.network_alerts_total || 0}
                    hint="Événements réseau exploitables en triage"
                  />
                  <OverviewCard
                    tone="danger"
                    label="Incidents réseau"
                    value={overview?.network_incidents_total || 0}
                    hint="Groupes corrélés et priorisés pour action"
                  />
                </div>
              </div>
            </div>
          </PageSection>

        
          <div className="dashboard-grid-2">
            <PageSection title="Activité">
              <div className="chart-box">
                <ResponsiveContainer width="100%" height={280}>
                  <LineChart data={activity}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#223250" />
                    <XAxis dataKey="time" stroke="#93a8c8" />
                    <YAxis stroke="#93a8c8" />
                    <Tooltip />
                    <Line
                      type="monotone"
                      dataKey="count"
                      stroke="#7db3ff"
                      strokeWidth={2}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </PageSection>

            <PageSection title="Répartition des sévérités">
              <div className="chart-box">
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      dataKey="value"
                      nameKey="name"
                      outerRadius={95}
                    >
                      <Cell fill="#ff6f6f" />
                      <Cell fill="#ffb07b" />
                      <Cell fill="#ffd47c" />
                      <Cell fill="#9fd0ff" />
                      <Cell fill="#89e6cb" />
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </PageSection>
          </div>

          <div className="dashboard-grid-2">
            <PageSection title="Actifs les plus exposés">
              <div className="chart-box">
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
              <div className="chart-box">
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
           <PageSection title="Derniers signaux">
            {loading ? (
              <p>Chargement des signaux...</p>
            ) : (
              <RecentDetections detections={detections.slice(0, 6)} />
            )}
          </PageSection>
        </>
      )}
    </div>
  );
}