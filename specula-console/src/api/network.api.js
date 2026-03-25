import { request } from "./client";

export async function getNetworkTheme(limit = 20) {
  return request(`/themes/network?limit=${limit}`);
}

export async function getNetworkAlerts(limit = 20) {
  return request(`/alerts/network?limit=${limit}`);
}

export async function getNetworkIncidents(limit = 20) {
  return request(`/incidents/network?limit=${limit}`);
}

export async function getDashboardNetworkOverview() {
  return request("/dashboard/network-overview");
}