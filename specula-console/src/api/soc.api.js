import { request } from "./client";

function normalizeIncidentResponse(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.incidents)) return payload.incidents;
  if (Array.isArray(payload?.data)) return payload.data;
  return [];
}

export async function getSocIncidents(limit = 50) {
  const payload = await request(`/incidents/soc?limit=${limit}`);
  return normalizeIncidentResponse(payload);
}

export async function getSocOverview(limit = 50) {
  return request(`/incidents/soc/overview?limit=${limit}`);
}