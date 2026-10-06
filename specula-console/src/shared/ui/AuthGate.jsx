import { useAuth } from "../providers/AuthProvider.jsx";
import LoginPage from "./LoginPage.jsx";

export default function AuthGate({ children }) {
  const { checking, authenticated } = useAuth();

  if (checking) return null;
  if (!authenticated) return <LoginPage />;
  return children;
}
