import { request } from "./client";

function normalizeIncidentResponse(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.incidents)) return payload.incidents;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.data?.items)) return payload.data.items;
  if (Array.isArray(payload?.data?.incidents)) return payload.data.incidents;
  return [];
}

export async function getSocIncidents(limit = 50) {
  const payload = await request(`/incidents/soc?limit=${limit}`);
  console.log("getSocIncidents payload", payload);
  return normalizeIncidentResponse(payload);
}

export async function getSocOverview(limit = 50) {
  return request(`/incidents/soc/overview?limit=${limit}`);
}