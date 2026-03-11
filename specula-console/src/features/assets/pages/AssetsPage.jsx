import { useEffect, useMemo, useState } from "react";
import { getAssets } from "../../../api/assets.api";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";

function getStatusClass(status) {
  const value = String(status || "").toLowerCase();
  if (value === "active") return "info";
  if (value === "inactive") return "medium";
  return "low";
}

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

  const activeCount = useMemo(
    () => assets.filter((asset) => asset.status === "active").length,
    [assets]
  );

  const inactiveCount = useMemo(
    () => assets.filter((asset) => asset.status !== "active").length,
    [assets]
  );

  const cards = [
    { label: "Total Assets", value: assets.length, tone: "primary" },
    { label: "Active Assets", value: activeCount, tone: "success" },
    { label: "Inactive Assets", value: inactiveCount, tone: "warning" },
  ];

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Assets"
        title="Assets Inventory"
        description="Vue consolidée des agents, plateformes, adresses IP et statuts remontés par Wazuh."
        badge={`${assets.length} assets`}
      />

      <MetricCards items={cards} />

      <PageSection title="Assets List">
        {error ? (
          <p className="error-text">{error}</p>
        ) : !assets.length ? (
          <p className="empty-state">No assets found.</p>
        ) : (
          <div className="entity-grid">
            {assets.map((asset, index) => (
              <article className="entity-card" key={asset.asset_id || asset.id || index}>
                <div className="entity-card-top">
                  <div>
                    <h3 className="entity-title">
                      {asset.name || asset.hostname || "Unknown asset"}
                    </h3>
                    <p className="entity-subtitle">
                      {asset.os_name || asset.platform || "Unknown platform"}
                    </p>
                  </div>

                  <span className={`severity-pill ${getStatusClass(asset.status)}`}>
                    {asset.status || "unknown"}
                  </span>
                </div>

                <div className="entity-meta-grid">
                  <div>
                    <span className="entity-label">IP</span>
                    <strong>{asset.ip_address || asset.ip || "-"}</strong>
                  </div>
                  <div>
                    <span className="entity-label">Type</span>
                    <strong>{asset.asset_type || asset.type || "-"}</strong>
                  </div>
                  <div>
                    <span className="entity-label">Manager</span>
                    <strong>{asset.manager || "-"}</strong>
                  </div>
                  <div>
                    <span className="entity-label">Last seen</span>
                    <strong>{asset.last_seen || "-"}</strong>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </PageSection>
    </div>
  );
}