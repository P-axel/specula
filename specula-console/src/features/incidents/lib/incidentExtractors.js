export function uniqStrings(values) {
  return [
    ...new Set(
      values
        .filter(Boolean)
        .map((value) => String(value).trim())
        .filter(Boolean)
    ),
  ];
}

export function extractCves(source) {
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

export function extractMitre(source) {
  const mitre = source?.rule?.mitre || source?.mitre || {};
  const raw = [
    ...(Array.isArray(mitre?.id) ? mitre.id : [mitre?.id]),
    ...(Array.isArray(mitre?.technique) ? mitre.technique : [mitre?.technique]),
    ...(Array.isArray(mitre?.tactic) ? mitre.tactic : [mitre?.tactic]),
  ];

  return uniqStrings(raw);
}

export function extractUsers(source) {
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

export function extractProcesses(source) {
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

export function extractFiles(source) {
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

export function extractRegistryKeys(source) {
  return uniqStrings([
    source?.registry_key,
    source?.registry?.key,
    source?.data?.registry_key,
    source?.win?.eventdata?.targetObject,
  ]);
}

export function extractPackageInfo(source) {
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

export function extractSuricataDetails(source) {
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

export function extractEvidence(source) {
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