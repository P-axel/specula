import { useEffect, useState } from "react";
import { fetchAssets } from "../api/assetsApi";
import AssetsTable from "../components/AssetsTable";

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
        setError("Impossible de charger les assets.");
      } finally {
        setLoading(false);
      }
    }

    loadAssets();
  }, []);

  if (loading) return <p>Chargement des assets...</p>;
  if (error) return <p>{error}</p>;

  return (
    <section>
      <h1>Assets</h1>
      <AssetsTable assets={assets} />
    </section>
  );
}