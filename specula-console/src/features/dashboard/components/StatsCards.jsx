export default function StatsCards({
  assetsCount,
  activeAssetsCount,
  inactiveAssetsCount,
  openAlertsCount,
  detectionsCount,
}) {
  const cards = [
    {
      label: "Assets Monitored",
      value: assetsCount,
      tone: "primary",
    },
    {
      label: "Active Agents",
      value: activeAssetsCount,
      tone: "success",
    },
    {
      label: "Inactive Agents",
      value: inactiveAssetsCount,
      tone: "warning",
    },
    {
      label: "Open Alerts",
      value: openAlertsCount,
      tone: "danger",
    },
    {
      label: "Detections",
      value: detectionsCount,
      tone: "info",
    },
  ];

  return (
    <div className="stats-grid modern">
      {cards.map((card) => (
        <div key={card.label} className={`stat-card modern ${card.tone}`}>
          <span className="stat-label">{card.label}</span>
          <strong className="stat-value">{card.value}</strong>
        </div>
      ))}
    </div>
  );
}