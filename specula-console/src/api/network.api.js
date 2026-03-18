import { request } from "./client";

export async function fetchNetworkTheme(limit = 20) {
  return request(`/themes/network?limit=${limit}`);
}

export async function fetchNetworkAlerts(limit = 20) {
  return request(`/alerts/network?limit=${limit}`);
}

export async function fetchNetworkIncidents(limit = 20) {
  return request(`/incidents/network?limit=${limit}`);
}

export async function fetchDashboardOverview() {
  return request("/dashboard/overview");
}

export async function fetchDashboardNetworkOverview() {
  return request("/dashboard/network-overview");
}