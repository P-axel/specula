import { request } from "./client.js";

export function getNotificationsConfig() {
  return request("/notifications/config");
}
