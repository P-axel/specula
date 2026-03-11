import { request } from "./client";

export async function getAssets() {
  return request("/assets");
}