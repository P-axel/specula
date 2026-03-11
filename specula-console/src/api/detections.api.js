import { request } from "./client";

export async function getDetections() {
  return request("/detections");
}