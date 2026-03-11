import { apiGet } from "../../../core/api/client";

export async function fetchAssets() {
  return apiGet("/assets");
}