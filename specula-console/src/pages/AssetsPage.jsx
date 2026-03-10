import { useEffect, useState } from "react";
import { fetchAssets } from "../api/assets";
import AssetsTable from "../components/assets/AssetsTable";

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadAssets() {
      try {
        const data = await fetchAssets();
        setAssets(data);
      } catch (err) {
        setError(err.message || "Erreur lors du chargement des assets");
      } finally {
        setLoading(false);
      }
    }

    loadAssets();
  }, []);

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2>Assets</h2>
          <p className="panel-subtitle">
            Inventaire normalisé remonté depuis le noyau Specula.
          </p>
        </div>

        <div className="panel-meta">
          <span className="badge">{assets.length} asset(s)</span>
        </div>
      </div>

      {loading && (
        <div className="state-box">
          <p>Chargement des assets...</p>
        </div>
      )}

      {!loading && error && (
        <div className="state-box state-error">
          <p>{error}</p>
        </div>
      )}

      {!loading && !error && <AssetsTable assets={assets} />}
    </section>
  );
}