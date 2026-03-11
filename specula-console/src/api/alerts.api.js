import { request } from "./client";

export async function getAlerts() {
  return request("/alerts");
}