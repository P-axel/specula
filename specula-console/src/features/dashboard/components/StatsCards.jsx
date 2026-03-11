export default function StatsCards({ assetsCount, openAlertsCount, detectionsCount }) {
  const cards = [
    { label: "Assets", value: assetsCount },
    { label: "Open Alerts", value: openAlertsCount },
    { label: "Detections", value: detectionsCount },
  ];

  return (
    <div className="stats-grid">
      {cards.map((card) => (
        <div key={card.label} className="stat-card">
          <span className="stat-label">{card.label}</span>
          <strong className="stat-value">{card.value}</strong>
        </div>
      ))}
    </div>
  );
}