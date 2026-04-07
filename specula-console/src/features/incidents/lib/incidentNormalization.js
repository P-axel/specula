import { formatEndpoint } from "./incidentFormatters";
import {
  extractCves,
  extractEvidence,
  extractFiles,
  extractMitre,
  extractPackageInfo,
  extractProcesses,
  extractRegistryKeys,
  extractSuricataDetails,
  extractUsers,
  uniqStrings,
} from "./incidentExtractors";

export function getPriorityLabel(value) {
  const normalized = String(value || "info").toLowerCase();

  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium")) return "medium";
  if (normalized.includes("low")) return "low";
  return "info";
}

export function normalizeEngine(value) {
  const raw = String(value || "").toLowerCase().trim();

  if (!raw) return "non précisé";
  if (raw.includes("wazuh")) return "wazuh";
  if (raw.includes("suricata")) return "suricata";
  if (raw.includes("specula")) return "specula";
  if (raw.includes("sysmon")) return "wazuh";
  if (raw.includes("ossec")) return "wazuh";

  return raw;
}

export function normalizeKind(value) {
  const raw = String(value || "").toLowerCase();

  if (
    raw.includes("vuln") ||
    raw.includes("cve") ||
    raw.includes("vulnerability")
  ) {
    return "vulnerability";
  }

  if (
    raw.includes("network") ||
    raw.includes("réseau") ||
    raw.includes("dns") ||
    raw.includes("http") ||
    raw.includes("tls")
  ) {
    return "network";
  }

  if (
    raw.includes("system") ||
    raw.includes("système") ||
    raw.includes("host") ||
    raw.includes("endpoint")
  ) {
    return "system";
  }

  if (
    raw.includes("identity") ||
    raw.includes("identité") ||
    raw.includes("iam") ||
    raw.includes("account") ||
    raw.includes("auth") ||
    raw.includes("mfa")
  ) {
    return "identity";
  }

  if (
    raw.includes("application") ||
    raw.includes("app") ||
    raw.includes("web") ||
    raw.includes("api")
  ) {
    return "application";
  }

  if (raw.includes("correlated") || raw.includes("corrélé")) {
    return "correlated";
  }

  return "generic";
}

export function detectKindFromValues(...values) {
  const haystack = values
    .flat()
    .filter(Boolean)
    .map((value) => String(value).toLowerCase())
    .join(" ");

  if (
    haystack.includes("cve") ||
    haystack.includes("vulnerability") ||
    haystack.includes("package") ||
    haystack.includes("vuln")
  ) {
    return "vulnerability";
  }

  if (
    haystack.includes("suricata") ||
    haystack.includes("network") ||
    haystack.includes("dns") ||
    haystack.includes("http") ||
    haystack.includes("tls") ||
    haystack.includes("scan") ||
    haystack.includes("port") ||
    haystack.includes("flow") ||
    haystack.includes("sni") ||
    haystack.includes("ja3")
  ) {
    return "network";
  }

  if (
    haystack.includes("wazuh") ||
    haystack.includes("system") ||
    haystack.includes("sysmon") ||
    haystack.includes("windows") ||
    haystack.includes("linux") ||
    haystack.includes("process") ||
    haystack.includes("fim") ||
    haystack.includes("agent") ||
    haystack.includes("registry") ||
    haystack.includes("service")
  ) {
    return "system";
  }

  if (
    haystack.includes("identity") ||
    haystack.includes("account") ||
    haystack.includes("user") ||
    haystack.includes("login") ||
    haystack.includes("authentication") ||
    haystack.includes("mfa") ||
    haystack.includes("iam")
  ) {
    return "identity";
  }

  if (
    haystack.includes("application") ||
    haystack.includes("web") ||
    haystack.includes("api") ||
    haystack.includes("backend") ||
    haystack.includes("frontend")
  ) {
    return "application";
  }

  if (
    haystack.includes("correlated") ||
    haystack.includes("correlation") ||
    haystack.includes("multi-engine")
  ) {
    return "correlated";
  }

  return "generic";
}

function stringifyHint(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value).toLowerCase();
    } catch {
      return "";
    }
  }
  return String(value).toLowerCase();
}

export function normalizeAlertItem(alert, index = 0) {
  const rawEngine =
    alert.engine ||
    alert.source_engine ||
    alert.detector ||
    alert.provider ||
    alert.manager?.name ||
    alert.decoder?.name;

  let engine = normalizeEngine(rawEngine);

  const wazuhHints = [
    alert.agent?.name,
    alert.agent_name,
    alert.rule?.groups,
    alert.rule?.description,
    alert.decoder?.name,
    alert.manager?.name,
    alert.location,
    alert.full_log,
    alert.data,
    alert.win?.eventdata,
    alert.sysmon,
    alert.syscheck,
  ];

  if (engine === "non précisé") {
    const joinedHints = wazuhHints
      .flatMap((value) => (Array.isArray(value) ? value : [value]))
      .map(stringifyHint)
      .filter(Boolean)
      .join(" ");

    if (
      joinedHints.includes("wazuh") ||
      joinedHints.includes("sysmon") ||
      joinedHints.includes("syscheck") ||
      joinedHints.includes("ossec") ||
      alert.agent?.name ||
      alert.agent_name ||
      alert.manager?.name ||
      alert.win?.eventdata ||
      alert.sysmon ||
      alert.syscheck
    ) {
      engine = "wazuh";
    }
  }

  const severity =
    alert.severity ||
    alert.priority ||
    alert.level ||
    alert.rule?.level ||
    "info";

  const srcIp = alert.src_ip || alert.data?.srcip || alert.data?.src_ip;
  const srcPort = alert.src_port || alert.data?.srcport || alert.data?.src_port;
  const destIp = alert.dest_ip || alert.data?.dstip || alert.data?.dest_ip;
  const destPort = alert.dest_port || alert.data?.dstport || alert.data?.dst_port;

  const srcLabel =
    alert.src_label ||
    alert.source_ip_label ||
    formatEndpoint(srcIp, srcPort);

  const destLabel =
    alert.dest_label ||
    alert.destination_ip_label ||
    formatEndpoint(destIp, destPort);

  const category =
    alert.category ||
    alert.group ||
    alert.rule_group ||
    alert.event_category ||
    (Array.isArray(alert.rule?.groups) ? alert.rule.groups.join(" • ") : null) ||
    alert.decoder?.name ||
    "Catégorie non précisée";

  const title =
    alert.title ||
    alert.rule_description ||
    alert.rule?.description ||
    alert.signature ||
    alert.summary ||
    alert.event_type ||
    alert.message ||
    "Alerte à qualifier";

  const assetName =
    alert.asset_name ||
    alert.agent_name ||
    alert.agent?.name ||
    alert.host ||
    alert.hostname ||
    alert.device_name ||
    alert.computer_name ||
    alert.manager?.name ||
    destIp ||
    srcIp ||
    "Actif non identifié";

  const hasNetworkFields = Boolean(srcIp || destIp);

  const description =
    alert.description ||
    alert.full_log ||
    alert.message ||
    alert.rule_description ||
    alert.rule?.description ||
    alert.summary ||
    (hasNetworkFields
      ? `${srcLabel} → ${destLabel}`
      : "Aucune description disponible.");

  const rawKind =
    alert.kind ||
    alert.incident_kind ||
    alert.family ||
    alert.type ||
    alert.event_type;

  const eventType =
    alert.event_type ||
    alert.type ||
    alert.rule?.groups?.[0] ||
    alert.decoder?.name ||
    "Type non précisé";

  const cves = extractCves(alert);
  const suricata = extractSuricataDetails(alert);

  const kind =
    normalizeKind(rawKind) !== "generic"
      ? normalizeKind(rawKind)
      : engine === "wazuh" && cves.length
      ? "vulnerability"
      : engine === "wazuh"
      ? "system"
      : engine === "suricata"
      ? "network"
      : detectKindFromValues(engine, category, title, description, eventType);

  const packageInfo = extractPackageInfo(alert);

  return {
    id:
      alert.id ||
      alert._id ||
      alert.uuid ||
      `${engine}-${alert.timestamp || alert.created_at || index}`,
    title,
    description,
    severity,
    risk_score:
      alert.risk_score ?? alert.rule_level ?? alert.rule?.level ?? alert.score ?? "-",
    engine,
    kind,
    asset_name: assetName,
    timestamp:
      alert.created_at ||
      alert.timestamp ||
      alert.last_seen ||
      alert["@timestamp"] ||
      null,
    category,
    event_type: eventType,
    src_ip: srcIp,
    src_port: srcPort,
    dest_ip: destIp,
    dest_port: destPort,
    src_label: srcLabel,
    dest_label: destLabel,
    protocol:
      alert.protocol_label ||
      alert.protocol ||
      alert.proto ||
      alert.data?.protocol ||
      suricata.app_proto ||
      "-",
    status: String(alert.status || "open").toLowerCase(),
    rule_id: alert.rule?.id || alert.rule_id || null,
    rule_groups: Array.isArray(alert.rule?.groups) ? alert.rule.groups : [],
    cves,
    mitre: extractMitre(alert),
    users: extractUsers(alert),
    processes: extractProcesses(alert),
    files: extractFiles(alert),
    registry_keys: extractRegistryKeys(alert),
    package_name: packageInfo.package_name,
    package_version: packageInfo.package_version,
    fixed_version: packageInfo.fixed_version,
    agent_name: alert.agent?.name || alert.agent_name || null,
    agent_id: alert.agent?.id || alert.agent_id || null,
    evidence: extractEvidence(alert),
    signature_id: suricata.signature_id,
    signature: suricata.signature,
    app_proto: suricata.app_proto,
    direction: suricata.direction,
    flow_id: suricata.flow_id,
    http_host: suricata.http_host,
    http_url: suricata.http_url,
    dns_query: suricata.dns_query,
    tls_sni: suricata.tls_sni,
    ja3: suricata.ja3,
    raw: alert,
  };
}

export function normalizeIncidentItem(incident, index = 0) {
  let engine = normalizeEngine(
    incident.engine ||
      incident.dominant_engine ||
      incident.source_engine ||
      incident.detector ||
      incident.provider ||
      incident.metadata?.engine ||
      incident.raw?.engine
  );

  if (engine === "non précisé") {
    const engineHints = [
      incident.asset_name,
      incident.hostname,
      incident.host,
      incident.agent_name,
      incident.metadata?.agent_name,
      incident.manager?.name,
      incident.title,
      incident.description,
      incident.summary,
      incident.category,
      incident.type,
      incident.theme,
    ]
      .map(stringifyHint)
      .filter(Boolean)
      .join(" ");

    if (
      engineHints.includes("wazuh") ||
      engineHints.includes("sysmon") ||
      engineHints.includes("syscheck") ||
      engineHints.includes("ossec")
    ) {
      engine = "wazuh";
    } else if (
      engineHints.includes("suricata") ||
      engineHints.includes("dns") ||
      engineHints.includes("http") ||
      engineHints.includes("tls") ||
      engineHints.includes("ja3") ||
      engineHints.includes("sni") ||
      engineHints.includes("flow")
    ) {
      engine = "suricata";
    } else if (engineHints.includes("specula")) {
      engine = "specula";
    }
  }

  const category =
    incident.category ||
    incident.type ||
    incident.event_category ||
    incident.theme ||
    incident.metadata?.category ||
    "Catégorie non précisée";

  const rawKind =
    incident.kind ||
    incident.incident_kind ||
    incident.family ||
    incident.metadata?.kind;

  const incidentSignals = Array.isArray(incident.signals) ? incident.signals : [];
  const normalizedSignals = incidentSignals.map((signal, idx) =>
    normalizeAlertItem(signal, idx)
  );

  const incidentSignalCves = uniqStrings(
    normalizedSignals.flatMap((signal) => signal.cves || [])
  );
  const incidentSignalMitre = uniqStrings(
    normalizedSignals.flatMap((signal) => signal.mitre || [])
  );
  const incidentSignalUsers = uniqStrings(
    normalizedSignals.flatMap((signal) => signal.users || [])
  );
  const incidentSignalProcesses = uniqStrings(
    normalizedSignals.flatMap((signal) => signal.processes || [])
  );
  const incidentSignalFiles = uniqStrings(
    normalizedSignals.flatMap((signal) => signal.files || [])
  );
  const incidentSignalRegistry = uniqStrings(
    normalizedSignals.flatMap((signal) => signal.registry_keys || [])
  );

  const kind =
    normalizeKind(rawKind) !== "generic"
      ? normalizeKind(rawKind)
      : incidentSignalCves.length
      ? "vulnerability"
      : engine === "suricata"
      ? "network"
      : engine === "wazuh"
      ? "system"
      : detectKindFromValues(
          engine,
          category,
          incident.title,
          incident.description,
          incident.summary
        );

  const timestamp =
    incident.last_seen ||
    incident.updated_at ||
    incident.timestamp ||
    incident.created_at ||
    null;

  const description =
    incident.description ||
    incident.summary ||
    incident.message ||
    "Aucune description disponible.";

  const firstSignal = normalizedSignals[0];
  const mergedSuricata = {
    signature_id: incident.signature_id || firstSignal?.signature_id || null,
    signature: incident.signature || firstSignal?.signature || null,
    app_proto: incident.app_proto || firstSignal?.app_proto || null,
    direction: incident.direction || firstSignal?.direction || null,
    flow_id: incident.flow_id || firstSignal?.flow_id || null,
    http_host: incident.http_host || firstSignal?.http_host || null,
    http_url: incident.http_url || firstSignal?.http_url || null,
    dns_query: incident.dns_query || firstSignal?.dns_query || null,
    tls_sni: incident.tls_sni || firstSignal?.tls_sni || null,
    ja3: incident.ja3 || firstSignal?.ja3 || null,
  };

  return {
    ...incident,
    id: incident.id || incident._id || `incident-${engine}-${index}`,
    title: incident.title || incident.name || "Incident à qualifier",
    description,
    severity: incident.severity || incident.priority || incident.risk_level || "info",
    risk_score: incident.risk_score ?? incident.score ?? 0,
    asset_name:
      incident.asset_name ||
      incident.hostname ||
      incident.host ||
      incident.agent_name ||
      incident.manager?.name ||
      (Array.isArray(incident.assets) && incident.assets.length
        ? incident.assets[0]
        : null) ||
      "Actif non identifié",
    category,
    engine,
    kind,
    status: String(incident.status || "open").toLowerCase(),
    timestamp,
    first_seen: incident.first_seen || incident.created_at || incident.timestamp || null,
    last_seen: incident.last_seen || incident.updated_at || incident.timestamp || null,
    detections_count:
      incident.detections_count ??
      incident.signals_count ??
      (Array.isArray(incident.signals) ? incident.signals.length : 0),
    event_type:
      incident.event_type ||
      incident.type ||
      incident.metadata?.event_type ||
      firstSignal?.event_type ||
      "Type non précisé",
    cves: uniqStrings([
      ...(Array.isArray(incident.cves) ? incident.cves : []),
      ...incidentSignalCves,
    ]),
    mitre: uniqStrings([
      ...(Array.isArray(incident.mitre) ? incident.mitre : []),
      ...incidentSignalMitre,
    ]),
    users: uniqStrings([
      ...(Array.isArray(incident.users) ? incident.users : []),
      ...incidentSignalUsers,
    ]),
    processes: uniqStrings([
      ...(Array.isArray(incident.processes) ? incident.processes : []),
      ...incidentSignalProcesses,
    ]),
    files: uniqStrings([
      ...(Array.isArray(incident.files) ? incident.files : []),
      ...incidentSignalFiles,
    ]),
    registry_keys: uniqStrings([
      ...(Array.isArray(incident.registry_keys) ? incident.registry_keys : []),
      ...incidentSignalRegistry,
    ]),
    package_name:
      incident.package_name ||
      incident.vulnerability?.package_name ||
      firstSignal?.package_name ||
      null,
    package_version:
      incident.package_version ||
      incident.vulnerability?.package_version ||
      firstSignal?.package_version ||
      null,
    fixed_version:
      incident.fixed_version ||
      incident.vulnerability?.fixed_version ||
      firstSignal?.fixed_version ||
      null,
    agent_name:
      incident.agent_name ||
      incident.metadata?.agent_name ||
      firstSignal?.agent_name ||
      null,
    agent_id:
      incident.agent_id ||
      incident.metadata?.agent_id ||
      firstSignal?.agent_id ||
      null,
    evidence: uniqStrings([
      incident.summary,
      incident.description,
      incident.message,
      ...normalizedSignals.flatMap((signal) => signal.evidence || []),
    ]).slice(0, 10),
    signature_id: mergedSuricata.signature_id,
    signature: mergedSuricata.signature,
    app_proto: mergedSuricata.app_proto,
    direction: mergedSuricata.direction,
    flow_id: mergedSuricata.flow_id,
    http_host: mergedSuricata.http_host,
    http_url: mergedSuricata.http_url,
    dns_query: mergedSuricata.dns_query,
    tls_sni: mergedSuricata.tls_sni,
    ja3: mergedSuricata.ja3,
  };
}