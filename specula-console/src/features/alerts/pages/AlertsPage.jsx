import { useEffect, useState } from "react";
import { getAlerts } from "../../../api/alerts.api";
import PageSection from "../../../shared/ui/PageSection";

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

  return (
    <div className="page">
      <PageSection title="Alerts">
        {error ? (
          <p className="error-text">{error}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, index) => (
                  <tr key={alert.id || index}>
                    <td>{alert.title || alert.name || "-"}</td>
                    <td>{alert.status || alert.state || "-"}</td>
                    <td>{alert.severity || alert.level || "-"}</td>
                    <td>{alert.created_at || alert.timestamp || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PageSection>
    </div>
  );
}