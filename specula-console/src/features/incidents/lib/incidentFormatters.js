export function safeText(value, fallback = "-") {
  if (value === null || value === undefined) return fallback;
  const text = String(value).trim();
  return text ? text : fallback;
}

export function formatEndpoint(ip, port) {
  if (!ip) return "-";
  if (port === undefined || port === null || port === "") return String(ip);
  if (String(ip).includes(":")) return `[${ip}]:${port}`;
  return `${ip}:${port}`;
}

export function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("fr-FR");
}

export function formatRenderableValue(value) {
  if (value === null || value === undefined || value === "") return "-";

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  if (Array.isArray(value)) {
    if (!value.length) return "-";
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

    try {
      return JSON.stringify(value);
    } catch {
      return "[objet]";
    }
  }

  return String(value);
}

export function formatPairsList(value) {
  if (!value) return [];

  if (Array.isArray(value)) {
    return value
      .map((item) => formatRenderableValue(item))
      .filter((item) => item && item !== "-");
  }

  return [formatRenderableValue(value)].filter((item) => item && item !== "-");
}