import { formatEndpoint, formatPairsList } from "./incidentFormatters";
import { getPriorityLabel, normalizeAlertItem } from "./incidentNormalization";

export function isWithinAge(timestamp, age) {
  if (!timestamp || age === "all") return true;

  const value = new Date(timestamp).getTime();
  if (Number.isNaN(value)) return true;

  const now = Date.now();
  const ageMap = {
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
    "30d": 30 * 24 * 60 * 60 * 1000,
  };

  const maxAge = ageMap[age];
  if (!maxAge) return true;

  return now - value <= maxAge;
}

export function filterIncidents(incidents, filters) {
  return incidents.filter((incident) => {
    const searchTarget = [
      incident.title,
      incident.description,
      incident.asset_name,
      incident.engine,
      incident.kind,
      incident.category,
      incident.event_type,
      incident.signature,
      incident.src_ip,
      incident.dest_ip,
      incident.http_host,
      incident.http_url,
      incident.dns_query,
      incident.tls_sni,
      incident.ja3,
      ...(incident.ip_pairs || []).map((p) => (typeof p === "string" ? p : `${p.src_ip} ${p.dest_ip}`)),
      ...(incident.cves || []),
      ...(incident.mitre || []),
      ...(incident.users || []),
      ...(incident.processes || []),
      ...(incident.files || []),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    const matchesSearch =
      !filters.search ||
      searchTarget.includes(filters.search.trim().toLowerCase());

    const matchesKind =
      filters.kind === "all" || incident.kind === filters.kind;

    const severityLabel = getPriorityLabel(incident.severity);
    const matchesSeverity =
      filters.severity === "all" || severityLabel === filters.severity;

    const incidentStatus = String(incident.status || "open").toLowerCase();
    const matchesStatus =
      filters.status === "all" || incidentStatus === filters.status;

    const matchesAge = isWithinAge(
      incident.last_seen || incident.updated_at || incident.timestamp,
      filters.age
    );

    return (
      matchesSearch &&
      matchesKind &&
      matchesSeverity &&
      matchesStatus &&
      matchesAge
    );
  });
}

export function extractIncidentSignals(incident, normalizedAlerts) {
  if (!incident) return [];

  const rawSignals = incident.signals || incident.metadata?.signals || [];
  if (Array.isArray(rawSignals) && rawSignals.length) {
    return rawSignals.map((signal, index) => normalizeAlertItem(signal, index));
  }

  if (incident.kind === "network") {
    const pairs = new Set(formatPairsList(incident.ip_pairs || incident.peer_ips));

    if (!pairs.size) return [];

    return normalizedAlerts.filter((normalized) => {
      if (normalized.kind !== "network") return false;

      const pair = `${formatEndpoint(
        normalized.src_ip,
        normalized.src_port
      )} → ${formatEndpoint(normalized.dest_ip, normalized.dest_port)}`;

      return pairs.has(pair);
    });
  }

  if (
    incident.kind === "system" ||
    incident.kind === "vulnerability" ||
    incident.engine === "wazuh"
  ) {
    return normalizedAlerts.filter((normalized) => {
      if (normalized.engine !== "wazuh") return false;

      const sameAsset =
        normalized.asset_name &&
        incident.asset_name &&
        String(normalized.asset_name).toLowerCase() ===
          String(incident.asset_name).toLowerCase();

      const sameTitle =
        normalized.title &&
        incident.title &&
        String(normalized.title).toLowerCase() ===
          String(incident.title).toLowerCase();

      const sameCategory =
        normalized.category &&
        incident.category &&
        String(normalized.category).toLowerCase() ===
          String(incident.category).toLowerCase();

      const shareCve =
        normalized.cves?.some((cve) => incident.cves?.includes(cve));

      return sameAsset && (sameTitle || sameCategory || shareCve);
    });
  }

  return [];
}