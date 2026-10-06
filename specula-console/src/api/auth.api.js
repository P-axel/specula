import { request } from "./client.js";

export function login(username, password) {
  return request("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

export function getAuthStatus() {
  return request("/auth/status");
}
