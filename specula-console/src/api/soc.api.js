const API_BASE = import.meta?.env?.VITE_SPECULA_API_BASE || "";

async function apiGet(path) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
    credentials: "include",
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Erreur API (${response.status}) sur ${path}${text ? ` : ${text}` : ""}`
    );
  }

  return response.json();
}

function mapNetworkIncidentToSoc(item, index = 0) {
  return {
    id: item.id || item.incident_id || `network-${index}`,
    title: item.title || item.signature || item.summary || "Incident réseau",
    status: item.status || "open",
    priority: item.priority || item.severity || "medium",
    risk_score: item.risk_score ?? item.score ?? 0,
    provider: item.provider || item.engine || item.detector || "suricata",
    theme: item.theme || "network",
    category: item.category || item.proto || "network",
    assets: item.assets || [],
    created_at: item.created_at || item.timestamp || null,
    updated_at: item.updated_at || item.last_seen || item.timestamp || null,
    summary: item.summary || item.message || item.signature || "",
    raw: item,
  };
}

export async function fetchSocIncidents() {
  try {
    return await apiGet("/incidents/soc");
  } catch (error) {
    const networkData = await apiGet("/incidents/network?limit=20");
    const networkItems = Array.isArray(networkData?.items) ? networkData.items : [];
    const items = networkItems.map(mapNetworkIncidentToSoc);

    return {
      count: items.length,
      providers: [...new Set(items.map((item) => item.provider).filter(Boolean))],
      items,
    };
  }
}

export async function fetchSocOverview() {
  try {
    return await apiGet("/incidents/soc/overview");
  } catch (error) {
    const incidents = await fetchSocIncidents();
    const items = Array.isArray(incidents?.items) ? incidents.items : [];

    return {
      total_incidents: items.length,
      open_incidents: items.filter((item) => String(item.status).toLowerCase() === "open").length,
      high_priority_incidents: items.filter((item) =>
        ["high", "haute", "critical", "critique", "p1", "p2"].includes(
          String(item.priority).toLowerCase()
        )
      ).length,
      max_risk_score: items.reduce((max, item) => {
        const value = Number(item.risk_score || 0);
        return value > max ? value : max;
      }, 0),
      engines: [...new Set(items.map((item) => item.provider).filter(Boolean))],
      themes: [...new Set(items.map((item) => item.theme).filter(Boolean))],
      categories: [...new Set(items.map((item) => item.category).filter(Boolean))],
      assets: [...new Set(items.flatMap((item) => item.assets || []))],
      items: [],
    };
  }
}