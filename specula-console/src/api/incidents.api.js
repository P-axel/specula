import { request } from "./client";

export async function getSocIncidents(limit = 50) {
  return request(`/incidents/soc?limit=${limit}`);
}