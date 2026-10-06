import { request } from "./client.js";

export function getNotificationsConfig() {
  return request("/notifications/config");
}

export function sendTestNotification() {
  return request("/notifications/test", { method: "POST" });
}
