import AssetsPage from "./pages/AssetsPage";

function App() {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="app-eyebrow">Security Visibility Platform</p>
          <h1>Specula Console</h1>
        </div>
      </header>

      <main className="app-content">
        <AssetsPage />
      </main>
    </div>
  );
}

export default App;