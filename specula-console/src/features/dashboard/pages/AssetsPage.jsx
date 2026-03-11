import { useEffect, useState } from "react";
import { getAssets } from "../../../api/assets.api";
import PageSection from "../../../shared/ui/PageSection";

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadAssets() {
      try {
        const data = await getAssets();
        setAssets(Array.isArray(data) ? data : data.items || []);
      } catch (err) {
        setError(err.message || "Failed to load assets.");
      }
    }

    loadAssets();
  }, []);

  return (
    <div className="page">
      <PageSection title="Assets">
        {error ? (
          <p className="error-text">{error}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset, index) => (
                  <tr key={asset.id || index}>
                    <td>{asset.name || asset.hostname || "-"}</td>
                    <td>{asset.type || "-"}</td>
                    <td>{asset.status || "-"}</td>
                    <td>{asset.ip || asset.ip_address || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PageSection>
    </div>
  );
}