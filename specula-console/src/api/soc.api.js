const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

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

async function tryGetIncidentsSoc(limit) {
  return apiGet(`/incidents/soc?limit=${limit}`);
}

async function tryGetIncidents(limit) {
  return apiGet(`/incidents?limit=${limit}`);
}

async function tryGetNetworkIncidents(limit) {
  return apiGet(`/incidents/network?limit=${limit}`);
}

function normalizeIncidentResponse(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (Array.isArray(payload?.items)) {
    return payload.items;
  }

  return [];
}

const USE_FIXTURES = true;

export async function fetchSocIncidents(limit = 50) {
  if (USE_FIXTURES) {
    const incidentsData = await tryGetIncidents(limit);
    return normalizeIncidentResponse(incidentsData);
  }

  try {
    const socData = await tryGetIncidentsSoc(limit);
    return normalizeIncidentResponse(socData);
  } catch {
    const incidentsData = await tryGetIncidents(limit);
    return normalizeIncidentResponse(incidentsData);
  }
}
export async function fetchSocOverview(limit = 50) {
  try {
    return await apiGet(`/incidents/soc/overview?limit=${limit}`);
  } catch (error) {
    const items = await fetchSocIncidents(limit);

    return {
      total_incidents: items.length,
      open_incidents: items.filter(
        (item) => String(item.status || "").toLowerCase() === "open"
      ).length,
      high_priority_incidents: items.filter((item) =>
        ["high", "haute", "critical", "critique", "p1", "p2"].includes(
          String(item.priority || item.severity || "").toLowerCase()
        )
      ).length,
      max_risk_score: items.reduce((max, item) => {
        const value = Number(item.risk_score ?? item.score ?? 0);
        return value > max ? value : max;
      }, 0),
      engines: [
        ...new Set(
          items
            .map((item) => item.provider || item.engine || item.detector)
            .filter(Boolean)
        ),
      ],
      themes: [
        ...new Set(
          items.map((item) => item.theme || item.kind || item.type).filter(Boolean)
        ),
      ],
      categories: [
        ...new Set(items.map((item) => item.category).filter(Boolean)),
      ],
      assets: [
        ...new Set(
          items.flatMap((item) => {
            if (Array.isArray(item.assets)) return item.assets;
            return [item.asset_name || item.hostname || item.host].filter(Boolean);
          })
        ),
      ],
      items: [],
    };
  }
}