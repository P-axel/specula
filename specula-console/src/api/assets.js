const API_BASE_URL = "http://127.0.0.1:8000";

export async function fetchAssets() {
  const response = await fetch(`${API_BASE_URL}/assets`);

  if (!response.ok) {
    throw new Error("Impossible de récupérer les assets");
  }

  return response.json();
}