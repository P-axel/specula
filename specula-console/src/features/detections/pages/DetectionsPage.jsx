import { useEffect, useState } from "react";
import { getDetections } from "../../../api/detections.api";
import PageSection from "../../../shared/ui/PageSection";

export default function DetectionsPage() {
  const [detections, setDetections] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDetections() {
      try {
        const data = await getDetections();
        setDetections(Array.isArray(data) ? data : data.items || []);
      } catch (err) {
        setError(err.message || "Failed to load detections.");
      }
    }

    loadDetections();
  }, []);

  return (
    <div className="page">
      <PageSection title="Detections">
        {error ? (
          <p className="error-text">{error}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Severity</th>
                  <th>Source</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {detections.map((item, index) => (
                  <tr key={item.id || index}>
                    <td>{item.name || item.rule_name || "-"}</td>
                    <td>{item.severity || item.level || "-"}</td>
                    <td>{item.source || item.agent || "-"}</td>
                    <td>{item.timestamp || item.created_at || "-"}</td>
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