import { useEffect, useMemo, useState } from "react";
import { getAlerts } from "../../../api/alerts.api";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";

function getAlertTone(severity) {
  const value = String(severity || "").toLowerCase();
  if (value.includes("critical")) return "critical";
  if (value.includes("high")) return "high";
  if (value.includes("medium")) return "medium";
  if (value.includes("low")) return "low";
  return "info";
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadAlerts() {
      try {
        const data = await getAlerts();
        setAlerts(Array.isArray(data) ? data : data.items || []);
      } catch (err) {
        setError(err.message || "Failed to load alerts.");
      }
    }

    loadAlerts();
  }, []);

  const cards = useMemo(
    () => [
      { label: "Alerts", value: alerts.length, tone: "danger" },
      {
        label: "Open Alerts",
        value: alerts.filter((alert) =>
          ["open", "OPEN"].includes(String(alert.status || alert.state))
        ).length,
        tone: "warning",
      },
    ],
    [alerts]
  );

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Alerts"
        title="Alert Center"
        description="Vue actionnable des alertes générées par Specula et les sources connectées."
        badge={`${alerts.length} alerts`}
      />

      <MetricCards items={cards} />

      <PageSection title="Open Alerts">
        {error ? (
          <p className="error-text">{error}</p>
        ) : !alerts.length ? (
          <p className="empty-state">No alerts available.</p>
        ) : (
          <div className="detection-list">
            {alerts.map((alert, index) => (
              <article className="detection-item" key={alert.id || index}>
                <div className={`severity-pill ${getAlertTone(alert.severity)}`}>
                  {alert.severity || "info"}
                </div>

                <div className="detection-body">
                  <h3 className="detection-title">
                    {alert.title || alert.name || "Untitled alert"}
                  </h3>

                  <div className="detection-meta">
                    <span>{alert.status || alert.state || "-"}</span>
                    <span>{alert.source || "specula"}</span>
                    <span>{alert.created_at || alert.timestamp || "-"}</span>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </PageSection>
    </div>
  );
}