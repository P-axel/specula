export default function MetricCards({ items = [] }) {
  return (
    <div className="stats-grid modern">
      {items.map((item) => (
        <div key={item.label} className={`stat-card modern ${item.tone || "info"}`}>
          <span className="stat-label">{item.label}</span>
          <strong className="stat-value">{item.value}</strong>
        </div>
      ))}
    </div>
  );
}