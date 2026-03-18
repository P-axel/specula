function getSeverityClass(severity) {
  const value = String(severity || "").toLowerCase();

  if (value.includes("critical")) return "critical";
  if (value.includes("high")) return "high";
  if (value.includes("medium")) return "medium";
  if (value.includes("low")) return "low";
  return "info";
}

function formatTimestamp(value) {
  if (!value) return "-";
  return String(value);
}

export default function RecentDetections({ detections = [] }) {
  if (!detections.length) {
    return <p className="empty-state">No recent detections.</p>;
  }

  return (
    <div className="detection-list">
      {detections.map((item, index) => {
        const severityClass = getSeverityClass(item.severity);
        const title = item.title || item.name || item.rule_name || "Unknown detection";
        const isIncident =
          String(item.type || "").toLowerCase() === "incident" ||
          Number(item.signals_count || 0) > 0;

        const primaryTimestamp = item.updated_at || item.timestamp || item.created_at;
        const createdAt = item.created_at || item.timestamp;
        const updatedAt = item.updated_at;

        const sourceLabel = item.source || item.agent || "unknown source";
        const assetLabel =
          item.asset_name || item.asset || item.hostname || item.asset_id || null;
        const categoryLabel = item.category || item.type || null;

        const signals =
          item.metadata?.signals && Array.isArray(item.metadata.signals)
            ? item.metadata.signals
            : Array.isArray(item.signals)
            ? item.signals
            : [];

        return (
          <article key={item.id || index} className="detection-item">
            <div className={`severity-pill ${severityClass}`}>
              {item.severity || "info"}
            </div>

            <div className="detection-body">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  gap: "1rem",
                  flexWrap: "wrap",
                }}
              >
                <div>
                  <h3 className="detection-title">{title}</h3>

                  {item.description ? (
                    <p
                      style={{
                        marginTop: "0.35rem",
                        marginBottom: 0,
                        opacity: 0.85,
                        fontSize: "0.95rem",
                      }}
                    >
                      {item.description}
                    </p>
                  ) : null}
                </div>

                <div
                  style={{
                    display: "flex",
                    gap: "0.4rem",
                    flexWrap: "wrap",
                    alignItems: "center",
                  }}
                >
                  {item.risk_score !== undefined && item.risk_score !== null ? (
                    <span className="meta-badge">
                      Risk {item.risk_score}
                    </span>
                  ) : null}

                  {item.risk_level ? (
                    <span className="meta-badge">
                      {item.risk_level}
                    </span>
                  ) : null}

                  {isIncident ? (
                    <span className="meta-badge">
                      {item.signals_count || 0} signals
                    </span>
                  ) : null}

                  {item.occurrences && Number(item.occurrences) > 1 ? (
                    <span className="meta-badge">
                      x{item.occurrences}
                    </span>
                  ) : null}

                  {isIncident ? (
                    <span className="meta-badge">Incident</span>
                  ) : (
                    <span className="meta-badge">Signal</span>
                  )}
                </div>
              </div>

              <div className="detection-meta" style={{ marginTop: "0.6rem", flexWrap: "wrap" }}>
                <span>{sourceLabel}</span>
                <span>{item.status || "status n/a"}</span>

                {assetLabel ? <span>{assetLabel}</span> : null}
                {categoryLabel ? <span>{categoryLabel}</span> : null}

                <span>{formatTimestamp(primaryTimestamp)}</span>

                {isIncident && createdAt && updatedAt && createdAt !== updatedAt ? (
                  <span>
                    {formatTimestamp(createdAt)} → {formatTimestamp(updatedAt)}
                  </span>
                ) : null}
              </div>

              {isIncident && signals.length > 0 ? (
                <div
                  style={{
                    marginTop: "0.85rem",
                    paddingTop: "0.75rem",
                    borderTop: "1px solid rgba(255,255,255,0.08)",
                  }}
                >
                  <div
                    style={{
                      fontSize: "0.75rem",
                      textTransform: "uppercase",
                      letterSpacing: "0.04em",
                      opacity: 0.7,
                      marginBottom: "0.45rem",
                    }}
                  >
                    Correlated signals
                  </div>

                  <div style={{ display: "grid", gap: "0.35rem" }}>
                    {signals.slice(0, 5).map((signal, signalIndex) => (
                      <div
                        key={`${signal.id || signalIndex}-${signal.timestamp || signalIndex}`}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          gap: "1rem",
                          fontSize: "0.9rem",
                          opacity: 0.9,
                        }}
                      >
                        <span>{signal.title || signal.name || "Unknown signal"}</span>
                        <span style={{ opacity: 0.7 }}>
                          {signal.severity || "n/a"}
                          {signal.risk_score !== undefined && signal.risk_score !== null
                            ? ` · Risk ${signal.risk_score}`
                            : ""}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          </article>
        );
      })}
    </div>
  );
}