import { request } from "./client";

export async function getDashboardOverview() {
  return request("/dashboard/overview");
}

export async function getSeverityDistribution() {
  return request("/dashboard/severity-distribution");
}

export async function getDashboardActivity() {
  return request("/dashboard/activity");
}

export async function getTopAssets() {
  return request("/dashboard/top-assets");
}

export async function getTopCategories() {
  return request("/dashboard/top-categories");
}