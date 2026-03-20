import { useEffect, useMemo, useState } from "react";
import { useSocData } from "../../../shared/providers/SocDataProvider";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import "./Incidents.css";

const KIND_LABELS = {
  network: "Réseau",
  system: "Système",
  identity: "Identité",
  application: "Application",
  correlated: "Corrélé",
  vulnerability: "Vulnérabilité",
  generic: "Autre",
};

function safeText(value, fallback = "-") {
  if (value === null || value === undefined) return fallback;
  const text = String(value).trim();
  return text ? text : fallback;
}

function formatEndpoint(ip, port) {
  if (!ip) return "-";
  if (port === undefined || port === null || port === "") return String(ip);
  if (String(ip).includes(":")) return `[${ip}]:${port}`;
  return `${ip}:${port}`;
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("fr-FR");
}

function uniqStrings(values) {
  return [
    ...new Set(
      values
        .filter(Boolean)
        .map((value) => String(value).trim())
        .filter(Boolean)
    ),
  ];
}

function getPriorityLabel(value) {
  const normalized = String(value || "info").toLowerCase();

  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium")) return "medium";
  if (normalized.includes("low")) return "low";
  return "info";
}

function normalizeEngine(value) {
  const raw = String(value || "").toLowerCase().trim();

  if (!raw) return "non précisé";
  if (raw.includes("wazuh")) return "wazuh";
  if (raw.includes("suricata")) return "suricata";
  if (raw.includes("specula")) return "specula";
  return raw;
}

function normalizeKind(value) {
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

function detectKindFromValues(...values) {
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

function formatPairsList(value) {
  if (!value) return [];

  if (Array.isArray(value)) {
    return value
      .map((item) => formatRenderableValue(item))
      .filter((item) => item && item !== "-");
  }

  return [formatRenderableValue(value)].filter((item) => item && item !== "-");
}

function isWithinAge(timestamp, age) {
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

function extractCves(source) {
  const candidates = [
    ...(Array.isArray(source?.cves) ? source.cves : []),
    ...(Array.isArray(source?.vulnerabilities) ? source.vulnerabilities : []),
    ...(Array.isArray(source?.rule?.cve) ? source.rule.cve : []),
    ...(Array.isArray(source?.rule?.cves) ? source.rule.cves : []),
    source?.cve,
    source?.vulnerability?.cve,
    source?.vulnerability?.id,
    source?.data?.cve,
    source?.data?.cves,
  ];

  return uniqStrings(
    candidates.flatMap((item) => (Array.isArray(item) ? item : [item]))
  );
}

function extractMitre(source) {
  const mitre = source?.rule?.mitre || source?.mitre || {};
  const raw = [
    ...(Array.isArray(mitre?.id) ? mitre.id : [mitre?.id]),
    ...(Array.isArray(mitre?.technique) ? mitre.technique : [mitre?.technique]),
    ...(Array.isArray(mitre?.tactic) ? mitre.tactic : [mitre?.tactic]),
  ];

  return uniqStrings(raw);
}

function extractUsers(source) {
  return uniqStrings([
    source?.user,
    source?.user_name,
    source?.username,
    source?.account,
    source?.account_name,
    source?.data?.srcuser,
    source?.data?.dstuser,
    source?.data?.user,
    source?.data?.username,
    source?.win?.eventdata?.targetUserName,
    source?.win?.eventdata?.subjectUserName,
  ]);
}

function extractProcesses(source) {
  return uniqStrings([
    source?.process_name,
    source?.process,
    source?.process_path,
    source?.image,
    source?.data?.process,
    source?.data?.process_name,
    source?.win?.eventdata?.image,
    source?.sysmon?.image,
    source?.syscheck?.path,
  ]);
}

function extractFiles(source) {
  return uniqStrings([
    source?.file,
    source?.file_path,
    source?.path,
    source?.location,
    source?.syscheck?.path,
    source?.data?.path,
    source?.data?.filename,
    source?.win?.eventdata?.targetFilename,
  ]);
}

function extractRegistryKeys(source) {
  return uniqStrings([
    source?.registry_key,
    source?.registry?.key,
    source?.data?.registry_key,
    source?.win?.eventdata?.targetObject,
  ]);
}

function extractPackageInfo(source) {
  return {
    package_name:
      source?.package_name ||
      source?.package?.name ||
      source?.vulnerability?.package_name ||
      source?.data?.package_name ||
      null,
    package_version:
      source?.package_version ||
      source?.package?.version ||
      source?.vulnerability?.package_version ||
      source?.data?.package_version ||
      null,
    fixed_version:
      source?.fixed_version ||
      source?.package?.fixed_version ||
      source?.vulnerability?.fixed_version ||
      source?.data?.fixed_version ||
      null,
  };
}

function extractSuricataDetails(source) {
  return {
    signature_id:
      source?.signature_id ||
      source?.alert?.signature_id ||
      source?.suricata?.eve?.alert?.signature_id ||
      null,
    signature:
      source?.signature ||
      source?.alert?.signature ||
      source?.suricata?.eve?.alert?.signature ||
      null,
    app_proto:
      source?.app_proto ||
      source?.suricata?.eve?.app_proto ||
      source?.data?.app_proto ||
      null,
    direction:
      source?.direction ||
      source?.suricata?.eve?.flow?.direction ||
      null,
    flow_id:
      source?.flow_id ||
      source?.suricata?.eve?.flow_id ||
      null,
    http_host:
      source?.http?.hostname ||
      source?.http?.host ||
      source?.data?.http_host ||
      null,
    http_url:
      source?.http?.url ||
      source?.data?.url ||
      null,
    dns_query:
      source?.dns?.rrname ||
      source?.dns?.query ||
      source?.data?.dns_query ||
      null,
    tls_sni:
      source?.tls?.sni ||
      source?.data?.tls_sni ||
      null,
    ja3:
      source?.tls?.ja3 ||
      source?.ja3 ||
      source?.data?.ja3 ||
      null,
  };
}

function extractEvidence(source) {
  return uniqStrings([
    source?.rule?.description,
    source?.rule_description,
    source?.summary,
    source?.message,
    source?.full_log,
    source?.decoder?.name,
    source?.location,
    source?.alert?.signature,
    source?.http?.url,
    source?.dns?.rrname,
    source?.tls?.sni,
  ]).slice(0, 8);
}

function normalizeAlertItem(alert, index = 0) {
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
    alert.rule?.groups,
    alert.rule?.description,
    alert.decoder?.name,
    alert.manager?.name,
    alert.location,
    alert.full_log,
    alert.data,
  ];

  if (
    engine === "non précisé" &&
    wazuhHints.some((value) => value !== undefined && value !== null)
  ) {
    engine = "wazuh";
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
    (hasNetworkFields ? `${srcLabel} → ${destLabel}` : "Aucune description disponible.");

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

function normalizeIncidentItem(incident, index = 0) {
  const engine = normalizeEngine(
    incident.engine ||
      incident.source_engine ||
      incident.detector ||
      incident.provider ||
      incident.metadata?.engine ||
      incident.raw?.engine
  );

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
  const normalizedSignals = incidentSignals.map((signal, idx) => normalizeAlertItem(signal, idx));

  const incidentSignalCves = uniqStrings(normalizedSignals.flatMap((signal) => signal.cves || []));
  const incidentSignalMitre = uniqStrings(normalizedSignals.flatMap((signal) => signal.mitre || []));
  const incidentSignalUsers = uniqStrings(normalizedSignals.flatMap((signal) => signal.users || []));
  const incidentSignalProcesses = uniqStrings(normalizedSignals.flatMap((signal) => signal.processes || []));
  const incidentSignalFiles = uniqStrings(normalizedSignals.flatMap((signal) => signal.files || []));
  const incidentSignalRegistry = uniqStrings(normalizedSignals.flatMap((signal) => signal.registry_keys || []));

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
    signature_id:
      incident.signature_id ||
      firstSignal?.signature_id ||
      null,
    signature:
      incident.signature ||
      firstSignal?.signature ||
      null,
    app_proto:
      incident.app_proto ||
      firstSignal?.app_proto ||
      null,
    direction:
      incident.direction ||
      firstSignal?.direction ||
      null,
    flow_id:
      incident.flow_id ||
      firstSignal?.flow_id ||
      null,
    http_host:
      incident.http_host ||
      firstSignal?.http_host ||
      null,
    http_url:
      incident.http_url ||
      firstSignal?.http_url ||
      null,
    dns_query:
      incident.dns_query ||
      firstSignal?.dns_query ||
      null,
    tls_sni:
      incident.tls_sni ||
      firstSignal?.tls_sni ||
      null,
    ja3:
      incident.ja3 ||
      firstSignal?.ja3 ||
      null,
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

function PriorityBadge({ value }) {
  const label = getPriorityLabel(value);

  return (
    <span className={`incident-badge incident-badge--${label}`}>
      {label}
    </span>
  );
}

function IncidentKindBadge({ kind }) {
  const normalized = normalizeKind(kind);
  const label = KIND_LABELS[normalized] || KIND_LABELS.generic;

  return (
    <span className={`incident-chip incident-chip--kind incident-chip--${normalized}`}>
      {label}
    </span>
  );
}

function IncidentEngineBadge({ engine }) {
  const normalized = normalizeEngine(engine);
  const label = normalized === "non précisé" ? "moteur non précisé" : normalized;

  return (
    <span className={`incident-chip incident-chip--engine incident-chip--${normalized.replace(/\s+/g, "-")}`}>
      {label}
    </span>
  );
}

function IncidentListItem({ incident, isSelected, onSelect }) {
  const count = incident.detections_count ?? 0;
  const hasCves = Array.isArray(incident.cves) && incident.cves.length > 0;

  return (
    <button
      type="button"
      className={`incident-list-item ${isSelected ? "is-selected" : ""}`}
      onClick={() => onSelect(incident)}
    >
      <div className="incident-list-item__top">
        <div className="incident-list-item__heading">
          <div className="incident-list-item__title">{incident.title || "-"}</div>
          <div className="incident-list-item__subtitle">
            {incident.asset_name || "Actif non identifié"}
          </div>
        </div>

        <PriorityBadge value={incident.severity} />
      </div>

      <div className="incident-list-item__meta">
        <IncidentKindBadge kind={incident.kind} />
        <IncidentEngineBadge engine={incident.engine} />
        {hasCves ? <span className="incident-chip">CVE</span> : null}
      </div>

      <p className="incident-list-item__description">
        {incident.description || "Aucune description disponible."}
      </p>

      <div className="incident-list-item__meta">
        <span>{count} signal(s)</span>
        <span>{formatDateTime(incident.last_seen || incident.timestamp)}</span>
      </div>
    </button>
  );
}

function DetailRow({ label, value }) {
  return (
    <div className="incident-detail-row">
      <div className="incident-detail-label">{label}</div>
      <div className="incident-detail-value">{formatRenderableValue(value)}</div>
    </div>
  );
}

function DetailTagList({ title, items, emptyLabel }) {
  return (
    <div className="incident-detail-block">
      <h4>{title}</h4>
      {items?.length ? (
        <div className="incident-chip-list">
          {items.map((item, index) => (
            <span className="incident-chip" key={`${title}-${index}-${item}`}>
              {item}
            </span>
          ))}
        </div>
      ) : (
        <p className="empty-state">{emptyLabel}</p>
      )}
    </div>
  );
}

function IncidentDetailPanel({ incident, linkedAlerts }) {
  if (!incident) {
    return (
      <div className="incident-panel-empty">
        <p className="empty-state">
          Sélectionne un incident pour ouvrir sa vue détaillée.
        </p>
      </div>
    );
  }

  const pairs = formatPairsList(incident.ip_pairs || incident.peer_ips);

  return (
    <div className="incident-detail-panel">
      <div className="incident-detail-header">
        <div className="incident-detail-kicker">Incident</div>
        <h3>{incident.title || "-"}</h3>
      </div>

      <div className="incident-chip-list" style={{ marginBottom: 16 }}>
        <PriorityBadge value={incident.severity} />
        <IncidentKindBadge kind={incident.kind} />
        <IncidentEngineBadge engine={incident.engine} />
      </div>

      <p className="incident-detail-description">
        {formatRenderableValue(incident.description || "-")}
      </p>

      <div className="incident-detail-grid">
        <DetailRow label="Famille" value={KIND_LABELS[incident.kind] || "Autre"} />
        <DetailRow label="Moteur de détection" value={incident.engine === "non précisé" ? "Moteur non identifié" : incident.engine} />
        <DetailRow label="Sévérité" value={incident.severity} />
        <DetailRow label="Score" value={incident.risk_score} />
        <DetailRow label="Actif" value={incident.asset_name} />
        <DetailRow label="Catégorie" value={incident.category} />
        <DetailRow label="Type" value={incident.event_type} />
        <DetailRow label="Statut" value={incident.status} />
        <DetailRow label="Agent" value={incident.agent_name} />
        <DetailRow label="Agent ID" value={incident.agent_id} />
        <DetailRow label="Premier vu" value={formatDateTime(incident.first_seen)} />
        <DetailRow label="Dernier vu" value={formatDateTime(incident.last_seen)} />
        <DetailRow label="Détections" value={incident.detections_count ?? 0} />
      </div>

      {incident.kind === "network" && (
        <>
          <DetailTagList
            title="Pairs IP"
            items={pairs}
            emptyLabel="Aucune paire IP disponible."
          />

          <div className="incident-detail-block">
            <h4>Détails réseau</h4>
            <div className="incident-detail-grid">
              <DetailRow label="Signature" value={incident.signature} />
              <DetailRow label="Signature ID" value={incident.signature_id} />
              <DetailRow label="Protocole applicatif" value={incident.app_proto} />
              <DetailRow label="Direction" value={incident.direction} />
              <DetailRow label="Flow ID" value={incident.flow_id} />
              <DetailRow label="HTTP host" value={incident.http_host} />
              <DetailRow label="HTTP URL" value={incident.http_url} />
              <DetailRow label="DNS query" value={incident.dns_query} />
              <DetailRow label="TLS SNI" value={incident.tls_sni} />
              <DetailRow label="JA3" value={incident.ja3} />
            </div>
          </div>
        </>
      )}

      {(incident.package_name || incident.package_version || incident.fixed_version) && (
        <div className="incident-detail-block">
          <h4>Vulnérabilité / package</h4>
          <div className="incident-detail-grid">
            <DetailRow label="Package" value={incident.package_name} />
            <DetailRow label="Version" value={incident.package_version} />
            <DetailRow label="Version corrigée" value={incident.fixed_version} />
          </div>
        </div>
      )}

      <DetailTagList
        title="CVE associés"
        items={incident.cves}
        emptyLabel="Aucun CVE associé."
      />

      <DetailTagList
        title="MITRE / ATT&CK"
        items={incident.mitre}
        emptyLabel="Aucune référence MITRE disponible."
      />

      <DetailTagList
        title="Utilisateurs impliqués"
        items={incident.users}
        emptyLabel="Aucun utilisateur identifié."
      />

      <DetailTagList
        title="Processus observés"
        items={incident.processes}
        emptyLabel="Aucun processus remonté."
      />

      <DetailTagList
        title="Fichiers / chemins"
        items={incident.files}
        emptyLabel="Aucun fichier remonté."
      />

      <DetailTagList
        title="Clés registre"
        items={incident.registry_keys}
        emptyLabel="Aucune clé registre remontée."
      />

      <DetailTagList
        title="Éléments d'analyse"
        items={incident.evidence}
        emptyLabel="Aucun élément complémentaire."
      />

      <div className="incident-detail-block">
        <h4>Signaux liés</h4>
        {!linkedAlerts.length ? (
          <p className="empty-state">Aucune alerte liée disponible.</p>
        ) : (
          <div className="incident-linked-alerts">
            {linkedAlerts.map((alert, index) => (
              <div
                className="incident-linked-alert"
                key={alert.id || `${alert.title}-${index}`}
              >
                <div className="incident-linked-alert__top">
                  <div className="incident-linked-alert__title">
                    {alert.title || "-"}
                  </div>
                  <PriorityBadge value={alert.severity} />
                </div>

                <div
                  className="incident-chip-list"
                  style={{ marginTop: 10, marginBottom: 10 }}
                >
                  <IncidentKindBadge kind={alert.kind} />
                  <IncidentEngineBadge engine={alert.engine} />
                </div>

                <div className="incident-linked-alert__description">
                  {alert.description || "-"}
                </div>

                <div className="incident-linked-alert__meta">
                  <span>{alert.category || "-"}</span>
                  <span>{alert.protocol || "-"}</span>
                  <span>{alert.asset_name || "-"}</span>
                  <span>{formatDateTime(alert.timestamp)}</span>
                </div>

                {(alert.cves?.length || alert.mitre?.length) ? (
                  <div className="incident-chip-list" style={{ marginTop: 10 }}>
                    {alert.cves?.map((cve) => (
                      <span className="incident-chip" key={`${alert.id}-cve-${cve}`}>
                        {cve}
                      </span>
                    ))}
                    {alert.mitre?.map((item) => (
                      <span className="incident-chip" key={`${alert.id}-mitre-${item}`}>
                        {item}
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function extractIncidentSignals(incident, normalizedAlerts) {
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

export default function IncidentsPage() {
  const { incidentsRaw, alertsRaw, refreshing, refreshSocData, error } = useSocData();

  const [selectedIncident, setSelectedIncident] = useState(null);
  const [filters, setFilters] = useState({
    search: "",
    kind: "all",
    severity: "all",
    status: "open",
    age: "all",
  });

  const incidentsData = useMemo(() => {
    return incidentsRaw.map((incident, index) => normalizeIncidentItem(incident, index));
  }, [incidentsRaw]);

  const normalizedAlerts = useMemo(() => {
    return alertsRaw.map((alert, index) => normalizeAlertItem(alert, index));
  }, [alertsRaw]);

  const highPriorityCount = useMemo(() => {
    return incidentsData.filter((incident) => {
      const priority = getPriorityLabel(incident.severity);
      return priority === "high" || priority === "critical";
    }).length;
  }, [incidentsData]);

  const vulnerabilityCount = useMemo(() => {
    return incidentsData.filter(
      (incident) =>
        incident.kind === "vulnerability" || (incident.cves && incident.cves.length > 0)
    ).length;
  }, [incidentsData]);

  const filteredIncidents = useMemo(() => {
    return incidentsData.filter((incident) => {
      const searchTarget = [
        incident.title,
        incident.description,
        incident.asset_name,
        incident.engine,
        incident.kind,
        incident.category,
        incident.event_type,
        incident.signature,
        incident.http_host,
        incident.http_url,
        incident.dns_query,
        incident.tls_sni,
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
  }, [incidentsData, filters]);

  useEffect(() => {
    if (!filteredIncidents.length) {
      setSelectedIncident(null);
      return;
    }

    const stillExists = filteredIncidents.some(
      (incident) => incident.id === selectedIncident?.id
    );

    if (!stillExists) {
      setSelectedIncident(filteredIncidents[0]);
    }
  }, [filteredIncidents, selectedIncident]);

  const linkedAlerts = useMemo(() => {
    return extractIncidentSignals(selectedIncident, normalizedAlerts);
  }, [selectedIncident, normalizedAlerts]);

  const cards = useMemo(
    () => [
      { label: "Incidents à traiter", value: incidentsData.length, tone: "warning" },
      { label: "Haute priorité", value: highPriorityCount, tone: "danger" },
      { label: "Incidents avec CVE", value: vulnerabilityCount, tone: "info" },
    ],
    [incidentsData.length, highPriorityCount, vulnerabilityCount]
  );

  return (
    <div className="page incidents-page">
      <PageHero
        eyebrow="Specula Incidents"
        title="Incidents à traiter"
        description="Vue d’investigation enrichie : corrélation, contexte technique, détails Wazuh utiles et contexte réseau Suricata."
        badge={`${filteredIncidents.length} incident(s)`}
      />

      <div
        style={{
          display: "flex",
          justifyContent: "flex-end",
          marginBottom: "16px",
        }}
      >
        <button
          type="button"
          onClick={refreshSocData}
          disabled={refreshing}
          className="incidents-filter-reset"
          style={{ opacity: refreshing ? 0.72 : 1 }}
        >
          {refreshing ? "Actualisation..." : "Rafraîchir les données"}
        </button>
      </div>

      <MetricCards items={cards} />

      <div className="incidents-filters">
        <div className="incidents-filter-group incidents-filter-group--search">
          <label className="incidents-filter-label" htmlFor="incident-search">
            Recherche
          </label>
          <input
            id="incident-search"
            className="incidents-filter-input"
            type="text"
            placeholder="Titre, actif, type, CVE, process, utilisateur, URL, DNS, SNI..."
            value={filters.search}
            onChange={(event) =>
              setFilters((prev) => ({ ...prev, search: event.target.value }))
            }
          />
        </div>

        <div className="incidents-filter-group">
          <label className="incidents-filter-label" htmlFor="incident-kind">
            Famille
          </label>
          <select
            id="incident-kind"
            className="incidents-filter-select"
            value={filters.kind}
            onChange={(event) =>
              setFilters((prev) => ({ ...prev, kind: event.target.value }))
            }
          >
            <option value="all">Toutes</option>
            <option value="network">Réseau</option>
            <option value="system">Système</option>
            <option value="identity">Identité</option>
            <option value="application">Application</option>
            <option value="vulnerability">Vulnérabilité</option>
            <option value="correlated">Corrélé</option>
          </select>
        </div>

        <div className="incidents-filter-group">
          <label className="incidents-filter-label" htmlFor="incident-severity">
            Sévérité
          </label>
          <select
            id="incident-severity"
            className="incidents-filter-select"
            value={filters.severity}
            onChange={(event) =>
              setFilters((prev) => ({ ...prev, severity: event.target.value }))
            }
          >
            <option value="all">Toutes</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>

        <div className="incidents-filter-group">
          <label className="incidents-filter-label" htmlFor="incident-status">
            Statut
          </label>
          <select
            id="incident-status"
            className="incidents-filter-select"
            value={filters.status}
            onChange={(event) =>
              setFilters((prev) => ({ ...prev, status: event.target.value }))
            }
          >
            <option value="all">Tous</option>
            <option value="open">Ouvert</option>
            <option value="investigating">En investigation</option>
            <option value="closed">Clos</option>
          </select>
        </div>

        <div className="incidents-filter-group">
          <label className="incidents-filter-label" htmlFor="incident-age">
            Période
          </label>
          <select
            id="incident-age"
            className="incidents-filter-select"
            value={filters.age}
            onChange={(event) =>
              setFilters((prev) => ({ ...prev, age: event.target.value }))
            }
          >
            <option value="all">Toute période</option>
            <option value="24h">24 dernières heures</option>
            <option value="7d">7 derniers jours</option>
            <option value="30d">30 derniers jours</option>
          </select>
        </div>

        <div className="incidents-filters__actions">
          <button
            type="button"
            className="incidents-filter-reset"
            onClick={() =>
              setFilters({
                search: "",
                kind: "all",
                severity: "all",
                status: "open",
                age: "all",
              })
            }
          >
            Réinitialiser
          </button>
        </div>
      </div>

      {error ? (
        <PageSection title="Erreur">
          <p className="error-text">{error}</p>
        </PageSection>
      ) : (
        <div className="incidents-master-detail">
          <PageSection
            title="Incidents corrélés"
            right={
              <span className="incidents-section-hint">
                Sélectionne un incident pour afficher son contexte enrichi
              </span>
            }
          >
            {!filteredIncidents.length ? (
              <p className="empty-state">Aucun incident correspondant aux filtres.</p>
            ) : (
              <div className="incident-list">
                {filteredIncidents.map((incident, index) => (
                  <IncidentListItem
                    key={incident.id || `${incident.title}-${index}`}
                    incident={incident}
                    isSelected={selectedIncident?.id === incident.id}
                    onSelect={setSelectedIncident}
                  />
                ))}
              </div>
            )}
          </PageSection>

          <PageSection
            title="Détail incident"
            right={
              selectedIncident ? (
                <span className="incidents-section-hint">
                  {selectedIncident.detections_count ?? linkedAlerts.length} signal(s)
                </span>
              ) : null
            }
          >
            <IncidentDetailPanel
              incident={selectedIncident}
              linkedAlerts={linkedAlerts}
            />
          </PageSection>
        </div>
      )}
    </div>
  );
}