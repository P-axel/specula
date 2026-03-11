export default function RecentDetections({ detections = [] }) {
  if (!detections.length) {
    return <p className="empty-state">No recent detections.</p>;
  }

  return (
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
              <td>{item.name || item.rule_name || "Unknown detection"}</td>
              <td>{item.severity || item.level || "-"}</td>
              <td>{item.source || item.agent || "-"}</td>
              <td>{item.timestamp || item.created_at || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}