import "./RecentDetections.css";

function formatTimestamp(value) {
  if (!value) return "-";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  return date.toLocaleString("fr-FR");
}

function normalizeSeverity(value) {
  const severity = String(value || "info").toLowerCase();

  if (severity.includes("critical")) return "critical";
  if (severity.includes("high")) return "high";
  if (severity.includes("medium")) return "medium";
  if (severity.includes("low")) return "low";
  return "info";
}

function getDisplayTitle(item) {
  return item.title || item.name || "Untitled detection";
}

function getDisplayDescription(item) {
  return item.description || item.summary || "No description available.";
}

function getDisplaySource(item) {
  return item.source || item.source_engine || item.engine || "specula";
}

function getDisplayAsset(item) {
  return item.asset_name || item.hostname || item.asset_id || "unknown";
}

export default function RecentDetections({ detections = [] }) {
  if (!detections.length) {
    return <p className="recent-detections__empty">No detections available.</p>;
  }

  return (
    <div className="recent-detections">
      {detections.map((item, index) => {
        const severity = normalizeSeverity(
          item.severity || item.priority || item.risk_level
        );

        return (
          <article
            className="recent-detection-card"
            key={item.id || `${getDisplayTitle(item)}-${index}`}
          >
            <div className="recent-detection-card__top">
              <div className="recent-detection-card__heading">
                <h3 className="recent-detection-card__title">
                  {getDisplayTitle(item)}
                </h3>
                <p className="recent-detection-card__description">
                  {getDisplayDescription(item)}
                </p>
              </div>

              <span
                className={`recent-detection-card__severity recent-detection-card__severity--${severity}`}
              >
                {severity}
              </span>
            </div>

            <div className="recent-detection-card__meta">
              <div className="recent-detection-card__meta-item">
                <span className="recent-detection-card__label">Source</span>
                <strong>{getDisplaySource(item)}</strong>
              </div>

              <div className="recent-detection-card__meta-item">
                <span className="recent-detection-card__label">Asset</span>
                <strong>{getDisplayAsset(item)}</strong>
              </div>

              <div className="recent-detection-card__meta-item">
                <span className="recent-detection-card__label">Category</span>
                <strong>{item.category || item.type || "-"}</strong>
              </div>

              <div className="recent-detection-card__meta-item">
                <span className="recent-detection-card__label">Timestamp</span>
                <strong>{formatTimestamp(item.timestamp || item.created_at)}</strong>
              </div>
            </div>
          </article>
        );
      })}
    </div>
  );
}