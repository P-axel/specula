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

function isEndpointObject(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      ("ip" in value || "port" in value)
  );
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

    if (isEndpointObject(value)) {
      return formatEndpoint(value.ip, value.port);
    }

    return JSON.stringify(value);
  }

  return String(value);
}

function normalizeLabel(value, fallbackIp, fallbackPort) {
  if (
    value === null ||
    value === undefined ||
    value === "" ||
    value === "unknown"
  ) {
    return formatEndpoint(fallbackIp, fallbackPort);
  }

  return formatRenderableValue(value);
}

function getPriority(item) {
  return item.priority || item.risk_level || item.severity || "info";
}

function getProtocol(item) {
  const value = item.protocol_label || item.protocol || item.proto;
  if (!value || value === "unknown") return "-";
  return formatRenderableValue(value);
}

function getEngine(item) {
  const candidate = item.source_engine || item.engine;

  if (!candidate) return "-";

  if (isEndpointObject(candidate)) {
    return "-";
  }

  if (typeof candidate === "string") {
    return candidate === "unknown" ? "-" : candidate;
  }

  return formatRenderableValue(candidate);
}

function getSource(item) {
  const direct = normalizeLabel(item.src_label, item.src_ip, item.src_port);
  if (direct !== "-") return direct;

  if (isEndpointObject(item.source)) {
    return formatEndpoint(item.source.ip, item.source.port);
  }

  if (isEndpointObject(item.source_engine)) {
    return formatEndpoint(item.source_engine.ip, item.source_engine.port);
  }

  return "-";
}

function getDestination(item) {
  const direct = normalizeLabel(item.dest_label, item.dest_ip, item.dest_port);
  if (direct !== "-") return direct;

  if (isEndpointObject(item.destination)) {
    return formatEndpoint(item.destination.ip, item.destination.port);
  }

  return "-";
}

export default function NetworkAlertsTable({
  items = [],
  onSelect,
  selectedId,
}) {
  if (!items.length) {
    return <div className="text-sm text-slate-400">Aucune alerte réseau.</div>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm text-slate-200">
        <thead>
          <tr className="border-b border-slate-800 text-left text-slate-400">
            <th className="px-3 py-2">Horodatage</th>
            <th className="px-3 py-2">Détection</th>
            <th className="px-3 py-2">Priorité</th>
            <th className="px-3 py-2">Score</th>
            <th className="px-3 py-2">Source</th>
            <th className="px-3 py-2">Destination</th>
            <th className="px-3 py-2">Proto</th>
            <th className="px-3 py-2">Moteur</th>
          </tr>
        </thead>

        <tbody>
          {items.map((item, index) => {
            const isSelected = selectedId && selectedId === item.id;
            const rowKey = `${item.id || "network-row"}-${item.timestamp || "na"}-${index}`;

            return (
              <tr
                key={rowKey}
                className={`border-b border-slate-900 align-top transition ${
                  onSelect ? "cursor-pointer hover:bg-slate-900/60" : ""
                } ${isSelected ? "bg-slate-900/80" : ""}`}
                onClick={() => onSelect?.(item)}
              >
                <td className="px-3 py-3 whitespace-nowrap text-slate-400">
                  {formatRenderableValue(item.timestamp)}
                </td>

                <td className="px-3 py-3">
                  <div className="font-medium text-slate-100">
                    {formatRenderableValue(item.title)}
                  </div>
                  <div className="mt-1 max-w-[520px] text-xs leading-5 text-slate-400">
                    {formatRenderableValue(
                      item.description || item.summary || item.category || "-"
                    )}
                  </div>
                </td>

                <td className="px-3 py-3 whitespace-nowrap">
                  <SeverityBadge severity={getPriority(item)} />
                </td>

                <td className="px-3 py-3 whitespace-nowrap">
                  <ScoreBadge score={item.risk_score} />
                </td>

                <td className="px-3 py-3 whitespace-nowrap font-mono text-xs text-slate-300">
                  {getSource(item)}
                </td>

                <td className="px-3 py-3 whitespace-nowrap font-mono text-xs text-slate-300">
                  {getDestination(item)}
                </td>

                <td className="px-3 py-3 whitespace-nowrap text-slate-300">
                  {getProtocol(item)}
                  <div className="mt-1 text-xs text-slate-500">
                    {formatRenderableValue(item.app_proto || item.direction || "-")}
                  </div>
                </td>

                <td className="px-3 py-3 whitespace-nowrap text-slate-300">
                  {getEngine(item)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}