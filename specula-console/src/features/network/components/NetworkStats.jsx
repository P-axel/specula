function StatCard({ label, value, variant }) {
  const styles = {
    detections: "border-blue-900 bg-blue-950/30",
    alerts: "border-yellow-900 bg-yellow-950/30",
    incidents: "border-red-900 bg-red-950/30",
  };

  return (
    <div
      className={`rounded-xl border p-4 shadow-sm ${styles[variant] || "border-slate-800 bg-slate-900"}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-sm text-slate-400">{label}</span>
      </div>

      <div className="mt-2 text-3xl font-semibold text-white">
        {value ?? 0}
      </div>

      <div className="mt-1 text-xs text-slate-500">
        {variant === "detections" && "Signaux réseau observés"}
        {variant === "alerts" && "Alertes nécessitant qualification"}
        {variant === "incidents" && "Incidents corrélés actifs"}
      </div>
    </div>
  );
}

export default function NetworkStats({
  detectionsCount = 0,
  alertsCount = 0,
  incidentsCount = 0,
}) {
  return (
    <div className="grid gap-4 md:grid-cols-3">
      <StatCard
        label="Détections réseau"
        value={detectionsCount}
        variant="detections"
      />

      <StatCard
        label="Alertes réseau"
        value={alertsCount}
        variant="alerts"
      />

      <StatCard
        label="Incidents réseau"
        value={incidentsCount}
        variant="incidents"
      />
    </div>
  );
}