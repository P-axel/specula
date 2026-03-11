export default function AppShell({ children }) {
  return (
    <div style={{ padding: "24px" }}>
      <header style={{ marginBottom: "24px" }}>
        <h1>Specula Console</h1>
      </header>
      <main>{children}</main>
    </div>
  );
}

