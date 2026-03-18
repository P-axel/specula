import React from "react";

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString("fr-FR");
}

function resolveIncidentId(item) {
  return item.id || item.incident_id || item.uuid || item.key || "";
}

function resolveIncidentTitle(item) {
  return (
    item.title ||
    item.name ||
    item.summary ||
    item.incident_title ||
    item.theme ||
    "Incident sans titre"
  );
}

function resolvePriority(item) {
  return item.priority || item.severity || item.level || "inconnu";
}

function resolveStatus(item) {
  return item.status || item.state || "inconnu";
}

function resolveRiskScore(item) {
  return item.risk_score ?? item.score ?? item.max_risk_score ?? "—";
}

function resolveEngine(item) {
  return item.provider || item.engine || item.source || "—";
}

function resolveUpdatedAt(item) {
  return (
    item.updated_at ||
    item.last_seen ||
    item.last_activity_at ||
    item.timestamp ||
    item.created_at ||
    null
  );
}

function priorityClass(priority) {
  const value = String(priority).toLowerCase();

  if (["critical", "critique", "p1", "sev1"].includes(value)) {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }
  if (["high", "haute", "élevée", "elevee", "p2", "sev2"].includes(value)) {
    return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  }
  if (["medium", "moyenne", "p3", "sev3"].includes(value)) {
    return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  }
  if (["low", "faible", "p4", "sev4"].includes(value)) {
    return "border-blue-500/30 bg-blue-500/10 text-blue-300";
  }

  return "border-slate-700 bg-slate-800/70 text-slate-300";
}

export default function SocIncidentsTable({
  items = [],
  selectedIncidentId,
  onSelectIncident,
}) {
  if (!items.length) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4 text-sm text-slate-400">
        Aucun incident SOC disponible.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/40">
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-900/80 text-slate-300">
            <tr className="border-b border-slate-800">
              <th className="px-4 py-3 text-left font-medium">Incident</th>
              <th className="px-4 py-3 text-left font-medium">Priorité</th>
              <th className="px-4 py-3 text-left font-medium">Statut</th>
              <th className="px-4 py-3 text-left font-medium">Score</th>
              <th className="px-4 py-3 text-left font-medium">Moteur</th>
              <th className="px-4 py-3 text-left font-medium">Dernière activité</th>
            </tr>
          </thead>

          <tbody>
            {items.map((item, index) => {
              const incidentId = resolveIncidentId(item);
              const isSelected = selectedIncidentId === incidentId;

              return (
                <tr
                  key={incidentId || `${resolveIncidentTitle(item)}-${index}`}
                  onClick={() => onSelectIncident?.(item)}
                  className={`cursor-pointer border-b border-slate-800/80 transition ${
                    isSelected
                      ? "bg-blue-500/10"
                      : "bg-transparent hover:bg-slate-900/70"
                  }`}
                >
                  <td className="px-4 py-3">
                    <div className="font-medium text-slate-100">
                      {resolveIncidentTitle(item)}
                    </div>
                    <div className="mt-1 text-xs text-slate-400">
                      ID: {incidentId || "—"}
                    </div>
                  </td>

                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-medium ${priorityClass(
                        resolvePriority(item)
                      )}`}
                    >
                      {String(resolvePriority(item))}
                    </span>
                  </td>

                  <td className="px-4 py-3 text-slate-300">
                    {String(resolveStatus(item))}
                  </td>

                  <td className="px-4 py-3 text-slate-300">
                    {resolveRiskScore(item)}
                  </td>

                  <td className="px-4 py-3 text-slate-300">
                    {resolveEngine(item)}
                  </td>

                  <td className="px-4 py-3 text-slate-400">
                    {formatDate(resolveUpdatedAt(item))}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}