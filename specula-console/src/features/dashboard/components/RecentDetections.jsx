function getSeverityClass(severity) {
  const value = String(severity || "").toLowerCase();

  if (value.includes("critical")) return "critical";
  if (value.includes("high")) return "high";
  if (value.includes("medium")) return "medium";
  if (value.includes("low")) return "low";
  return "info";
}

export default function RecentDetections({ detections = [] }) {
  if (!detections.length) {
    return <p className="empty-state">No recent detections.</p>;
  }

  return (
    <div className="detection-list">
      {detections.map((item, index) => {
        const severityClass = getSeverityClass(item.severity);

        return (
          <article key={item.id || index} className="detection-item">
            <div className={`severity-pill ${severityClass}`}>
              {item.severity || "info"}
            </div>

            <div className="detection-body">
              <h3 className="detection-title">
                {item.name || item.rule_name || "Unknown detection"}
              </h3>

              <div className="detection-meta">
                <span>{item.source || item.agent || "unknown source"}</span>
                <span>{item.status || "status n/a"}</span>
                <span>{item.timestamp || item.created_at || "-"}</span>
              </div>
            </div>
          </article>
        );
      })}
    </div>
  );
}