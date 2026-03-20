import "./MetricCards.css";

export default function MetricCards({ items = [] }) {
  return (
    <div className="metric-cards">
      {items.map((item) => (
        <div
          key={item.label}
          className={`metric-card metric-card--${item.tone || "info"}`}
        >
          <span className="metric-card__label">{item.label}</span>
          <strong className="metric-card__value">{item.value}</strong>
        </div>
      ))}
    </div>
  );
}