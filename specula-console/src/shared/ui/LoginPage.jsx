import { useState } from "react";
import { useAuth } from "../providers/AuthProvider.jsx";

export default function LoginPage() {
  const { login, error } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    await login(username, password);
    setLoading(false);
  }

  return (
    <div style={{
      minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center",
      background: "#06131c",
    }}>
      <form onSubmit={handleSubmit} style={{
        background: "#082030", border: "1px solid #24607e", borderRadius: "12px",
        padding: "40px 48px", width: "360px", display: "flex", flexDirection: "column", gap: "20px",
      }}>
        <div>
          <div style={{ color: "#00e5ff", fontSize: "0.75rem", letterSpacing: "0.12em", marginBottom: "6px" }}>
            SPECULA SOC
          </div>
          <h1 style={{ color: "#cce4f4", fontSize: "1.5rem", margin: 0 }}>Connexion</h1>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <input
            type="text"
            placeholder="Identifiant"
            value={username}
            onChange={e => setUsername(e.target.value)}
            autoFocus
            required
            style={inputStyle}
          />
          <input
            type="password"
            placeholder="Mot de passe"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
            style={inputStyle}
          />
        </div>

        {error && (
          <p style={{ color: "#ff6f6f", fontSize: "0.85rem", margin: 0 }}>{error}</p>
        )}

        <button
          type="submit"
          disabled={loading}
          style={{
            background: loading ? "#183f58" : "#2160ff",
            color: "#fff", border: "none", borderRadius: "8px",
            padding: "12px", fontWeight: 600, fontSize: "0.95rem",
            cursor: loading ? "not-allowed" : "pointer",
          }}
        >
          {loading ? "Connexion…" : "Se connecter"}
        </button>
      </form>
    </div>
  );
}

const inputStyle = {
  background: "#06131c", border: "1px solid #24607e", borderRadius: "6px",
  color: "#cce4f4", padding: "10px 14px", fontSize: "0.9rem", outline: "none",
  width: "100%", boxSizing: "border-box",
};
