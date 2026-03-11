import { request } from "./client";

export async function getEvents() {
  return request("/events");
}