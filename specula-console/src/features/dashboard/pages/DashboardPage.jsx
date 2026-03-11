import { useEffect, useState } from "react";
import { getAssets } from "../../../api/assets.api";
import { getAlerts } from "../../../api/alerts.api";
import { getDetections } from "../../../api/detections.api";
import PageSection from "../../../shared/ui/PageSection";
import StatsCards from "../components/StatsCards";
import RecentDetections from "../components/RecentDetections";

export default function DashboardPage() {
  const [assets, setAssets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDashboard() {
      try {
        setLoading(true);
        setError("");

        const [assetsData, alertsData, detectionsData] = await Promise.all([
          getAssets(),
          getAlerts(),
          getDetections(),
        ]);

        setAssets(Array.isArray(assetsData) ? assetsData : assetsData.items || []);
        setAlerts(Array.isArray(alertsData) ? alertsData : alertsData.items || []);
        setDetections(
          Array.isArray(detectionsData)
            ? detectionsData
            : detectionsData.items || []
        );
      } catch (err) {
        setError(err.message || "Failed to load dashboard.");
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

  const openAlertsCount = alerts.filter(
    (alert) =>
      alert.status === "open" ||
      alert.state === "open" ||
      alert.status === "OPEN"
  ).length;

  const recentDetections = detections.slice(0, 5);

  return (
    <div className="page">
      <PageSection title="Overview">
        {loading ? (
          <p>Loading dashboard...</p>
        ) : error ? (
          <p className="error-text">{error}</p>
        ) : (
          <StatsCards
            assetsCount={assets.length}
            openAlertsCount={openAlertsCount}
            detectionsCount={detections.length}
          />
        )}
      </PageSection>

      <PageSection title="Recent Detections">
        {loading ? (
          <p>Loading detections...</p>
        ) : error ? (
          <p className="error-text">{error}</p>
        ) : (
          <RecentDetections detections={recentDetections} />
        )}
      </PageSection>
    </div>
  );
}