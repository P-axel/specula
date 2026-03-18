function SeverityBadge({ severity }) {
  const value = String(severity || "info").toLowerCase();

  const styles = {
    critical: "bg-red-950 text-red-200 border border-red-800",
    high: "bg-orange-950 text-orange-200 border border-orange-800",
    medium: "bg-yellow-950 text-yellow-200 border border-yellow-800",
    low: "bg-blue-950 text-blue-200 border border-blue-800",
    info: "bg-slate-800 text-slate-200 border border-slate-700",
  };

  return (
    <span
      className={`inline-flex rounded-full px-2 py-1 text-[11px] font-semibold uppercase tracking-wide ${styles[value] || styles.info}`}
    >
      {value}
    </span>
  );
}

function ScoreBadge({ score }) {
  const numeric = Number(score || 0);

  let styles = "bg-slate-900 text-slate-300 border border-slate-700";
  if (numeric >= 80) styles = "bg-red-950 text-red-200 border border-red-800";
  else if (numeric >= 60) styles = "bg-orange-950 text-orange-200 border border-orange-800";
  else if (numeric >= 35) styles = "bg-yellow-950 text-yellow-200 border border-yellow-800";
  else if (numeric > 0) styles = "bg-blue-950 text-blue-200 border border-blue-800";

  return (
    <span
      className={`inline-flex min-w-[44px] justify-center rounded-full px-2 py-1 text-[11px] font-semibold ${styles}`}
    >
      {numeric || "-"}
    </span>
  );
}

function formatEndpoint(ip, port) {
  if (!ip) return "-";
  if (port === undefined || port === null || port === "") return String(ip);
  if (String(ip).includes(":")) return `[${ip}]:${port}`;
  return `${ip}:${port}`;
}

function formatRenderableValue(value) {
  if (value === null || value === undefined || value === "") return "-";

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => formatRenderableValue(item)).join(" • ");
  }

  if (typeof value === "object") {
    if ("src_ip" in value || "dest_ip" in value) {
      const left = formatEndpoint(value.src_ip, value.src_port);
      const right = formatEndpoint(value.dest_ip, value.dest_port);
      return `${left} → ${right}`;
    }

    if ("ip" in value || "port" in value) {
      return formatEndpoint(value.ip, value.port);
    }

    return JSON.stringify(value);
  }

  return String(value);
}

function getPriority(item) {
  return item.priority || item.risk_level || item.severity || "info";
}

function getPeerIps(item) {
  return item.ip_pairs || item.peer_ips || [];
}

function getEngines(item) {
  const value = item.engines || item.source_engines || [];
  return Array.isArray(value) ? value : [value];
}

export default function NetworkIncidentsTable({
  items = [],
  onSelect,
  selectedId,
}) {
  if (!items.length) {
    return <div className="text-sm text-slate-400">Aucun incident réseau.</div>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm text-slate-200">
        <thead>
          <tr className="border-b border-slate-800 text-left text-slate-400">
            <th className="px-3 py-2">Incident</th>
            <th className="px-3 py-2">Priorité</th>
            <th className="px-3 py-2">Score</th>
            <th className="px-3 py-2">Premier vu</th>
            <th className="px-3 py-2">Dernier vu</th>
            <th className="px-3 py-2">Détections</th>
            <th className="px-3 py-2">Pairs IP</th>
            <th className="px-3 py-2">Moteurs</th>
          </tr>
        </thead>

        <tbody>
          {items.map((item, index) => {
            const isSelected = selectedId && selectedId === item.id;
            const rowKey = `${item.id || "incident-row"}-${item.first_seen || "na"}-${index}`;

            const engines = getEngines(item);

            return (
              <tr
                key={rowKey}
                className={`border-b border-slate-900 align-top transition ${
                  onSelect ? "cursor-pointer hover:bg-slate-900/60" : ""
                } ${isSelected ? "bg-slate-900/80" : ""}`}
                onClick={() => onSelect?.(item)}
              >
                <td className="px-3 py-3">
                  <div className="font-medium text-slate-100">
                    {formatRenderableValue(item.title)}
                  </div>
                  <div className="mt-1 max-w-[420px] text-xs leading-5 text-slate-400">
                    {formatRenderableValue(item.description || item.asset_name || "-")}
                  </div>
                </td>

                <td className="px-3 py-3 whitespace-nowrap">
                  <SeverityBadge severity={getPriority(item)} />
                </td>

                <td className="px-3 py-3 whitespace-nowrap">
                  <ScoreBadge score={item.risk_score} />
                </td>

                <td className="px-3 py-3 whitespace-nowrap text-slate-400">
                  {formatRenderableValue(item.first_seen)}
                </td>

                <td className="px-3 py-3 whitespace-nowrap text-slate-400">
                  {formatRenderableValue(item.last_seen)}
                </td>

                <td className="px-3 py-3 whitespace-nowrap text-slate-200">
                  {formatRenderableValue(
                    item.detections_count ?? item.signals_count ?? 0
                  )}
                </td>

                <td className="px-3 py-3 text-xs leading-5 text-slate-300">
                  <div className="max-w-[360px]">
                    {formatRenderableValue(getPeerIps(item))}
                  </div>
                </td>

                <td className="px-3 py-3 text-slate-300">
                  <div className="flex flex-wrap gap-1">
                    {engines.length ? (
                      engines.map((engine, engineIndex) => (
                        <span
                          key={`${formatRenderableValue(engine)}-${engineIndex}`}
                          className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] uppercase tracking-wide text-slate-300"
                        >
                          {formatRenderableValue(engine)}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500">-</span>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}