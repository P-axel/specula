const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const DEFAULT_TIMEOUT_MS = 15_000;
const TOKEN_KEY = "specula_token";

export const tokenStore = {
  get: ()        => localStorage.getItem(TOKEN_KEY),
  set: (token)   => localStorage.setItem(TOKEN_KEY, token),
  clear: ()      => localStorage.removeItem(TOKEN_KEY),
};

export async function request(path, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const token = tokenStore.get();
  const authHeader = token ? { Authorization: `Bearer ${token}` } : {};

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: { ...(options.headers || {}), ...authHeader },
      signal: controller.signal,
    });

    if (response.status === 401) {
      tokenStore.clear();
      window.dispatchEvent(new CustomEvent("specula:unauthorized"));
      throw new Error("Non authentifié");
    }

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`API error ${response.status}: ${text}`);
    }

    return response.json();
  } catch (err) {
    if (err.name === "AbortError") throw new Error(`Timeout: ${path}`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
