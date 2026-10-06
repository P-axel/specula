import { useAuth } from "../../shared/providers/AuthProvider.jsx";

export default function Header() {
  const { authEnabled, logout } = useAuth();

  return (
    <header className="header">
      <div>
        <h1 className="header-title">Specula Console</h1>
        <p className="header-subtitle">Security Operations Center</p>
      </div>

      <div className="header-actions">
        <span className="header-badge">SOC</span>
        {authEnabled && (
          <button
            onClick={logout}
            style={{
              background: "none", border: "1px solid #24607e", borderRadius: "6px",
              color: "#6899b4", padding: "6px 14px", fontSize: "0.8rem",
              cursor: "pointer",
            }}
          >
            Déconnexion
          </button>
        )}
      </div>
    </header>
  );
}
