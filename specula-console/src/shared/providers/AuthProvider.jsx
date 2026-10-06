import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { login as apiLogin, getAuthStatus } from "../../api/auth.api.js";
import { tokenStore } from "../../api/client.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authenticated, setAuthenticated] = useState(!!tokenStore.get());
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getAuthStatus()
      .then(({ auth_enabled }) => {
        setAuthEnabled(auth_enabled);
        if (!auth_enabled) setAuthenticated(true);
      })
      .catch(() => setAuthenticated(true))  // si /auth/status inaccessible → mode dégradé
      .finally(() => setChecking(false));
  }, []);

  useEffect(() => {
    const handler = () => { setAuthenticated(false); };
    window.addEventListener("specula:unauthorized", handler);
    return () => window.removeEventListener("specula:unauthorized", handler);
  }, []);

  const login = useCallback(async (username, password) => {
    setError("");
    try {
      const { access_token } = await apiLogin(username, password);
      tokenStore.set(access_token);
      setAuthenticated(true);
    } catch {
      setError("Identifiants incorrects.");
    }
  }, []);

  const logout = useCallback(() => {
    tokenStore.clear();
    setAuthenticated(false);
  }, []);

  return (
    <AuthContext.Provider value={{ authEnabled, authenticated, checking, error, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
