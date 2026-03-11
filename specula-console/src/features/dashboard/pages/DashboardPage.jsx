import { useEffect, useState } from "react";
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
  Cell,
  BarChart,
  Bar,
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

export default function DashboardPage() {
  const [overview, setOverview] = useState(null);
  const [severity, setSeverity] = useState(null);
  const [activity, setActivity] = useState([]);
  const [topAssets, setTopAssets] = useState([]);
  const [topCategories, setTopCategories] = useState([]);
  const [detections, setDetections] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDashboard() {
      try {
        setError("");

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
        setActivity(activityData);
        setTopAssets(topAssetsData);
        setTopCategories(topCategoriesData);
        setDetections(Array.isArray(detectionsData) ? detectionsData : []);
      } catch (err) {
        setError(err.message || "Failed to load dashboard.");
      }
    }

    loadDashboard();
  }, []);

  const cards = overview
    ? [
        { label: "Assets", value: overview.assets_total, tone: "primary" },
        { label: "Active Agents", value: overview.assets_active, tone: "success" },
        { label: "Inactive Agents", value: overview.assets_inactive, tone: "warning" },
        { label: "Open Alerts", value: overview.alerts_open, tone: "danger" },
        { label: "Detections", value: overview.detections_total, tone: "info" },
      ]
    : [];

  const severityData = severity
    ? [
        { name: "Critical", value: severity.critical || 0 },
        { name: "High", value: severity.high || 0 },
        { name: "Medium", value: severity.medium || 0 },
        { name: "Low", value: severity.low || 0 },
        { name: "Info", value: severity.info || 0 },
      ]
    : [];

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Security Operations"
        title="SOC Overview"
        description="Vue synthétique, visuelle et exploitable des actifs, signaux et tendances de sécurité."
        badge={overview ? `${overview.assets_total} monitored assets` : "Loading..."}
      />

      {error ? (
        <PageSection title="Dashboard">
          <p className="error-text">{error}</p>
        </PageSection>
      ) : (
        <>
          <MetricCards items={cards} />

          <div className="dashboard-grid-2">
            <PageSection title="Activity Timeline">
              <div className="chart-box">
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

            <PageSection title="Severity Distribution">
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
            <PageSection title="Top Assets">
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

            <PageSection title="Top Categories">
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

          <PageSection title="Recent Detections">
            <RecentDetections detections={detections.slice(0, 6)} />
          </PageSection>
        </>
      )}
    </div>
  );
}