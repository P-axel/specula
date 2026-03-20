import { useMemo } from "react";
import { useSocData } from "../../../shared/providers/SocDataProvider";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import "./AssetsPage.css";

function getStatusClass(status) {
  const value = String(status || "").toLowerCase();

  if (value === "active") return "info";
  if (value === "inactive" || value === "disconnected") return "medium";
  return "low";
}

function formatStatus(status) {
  const value = String(status || "").toLowerCase();

  if (value === "active") return "active";
  if (value === "inactive" || value === "disconnected") return "inactive";
  return "unknown";
}

function normalizeAsset(asset) {
  const rawName = asset.name || asset.hostname || "Unknown asset";
  const rawType = asset.asset_type || asset.type || "unknown";
  const rawPlatform = asset.os_name || asset.platform || "Unknown platform";
  const rawManager = asset.manager || "-";
  const rawLastSeen = asset.last_seen || "-";
  const rawStatus = formatStatus(asset.status);

  const isCore =
    rawName === "wazuh.manager" || String(rawType).toLowerCase() === "manager";

  const isHostAgent = rawName === "specula.agent";
  const isInfiniteLastSeen =
    typeof rawLastSeen === "string" && rawLastSeen.startsWith("9999-12-31");

  let displayName = rawName;
  let displayType = rawType;
  let displayRole = null;

  if (isCore) {
    displayName = "Specula Core";
    displayType = "core";
    displayRole = "Internal";
  } else if (isHostAgent) {
    displayName = "Specula Host Agent";
    displayType = "host";
    displayRole = "Primary";
  }

  const displayManager =
    rawManager === "wazuh.manager" ? "Specula Core" : rawManager;

  const displayLastSeen =
    isCore && isInfiniteLastSeen ? "Always active" : rawLastSeen;

  return {
    ...asset,
    displayName,
    displayType,
    displayRole,
    displayPlatform: rawPlatform,
    displayManager,
    displayLastSeen,
    displayStatus: rawStatus,
    isCore,
    isHostAgent,
  };
}

export default function AssetsPage() {
  const socData = useSocData();
  const assetsRaw = Array.isArray(socData?.assetsRaw) ? socData.assetsRaw : [];
  const error = socData?.error || "";

  const normalizedAssets = useMemo(() => {
    return assetsRaw.map((asset) => normalizeAsset(asset));
  }, [assetsRaw]);

  const activeCount = useMemo(() => {
    return normalizedAssets.filter((asset) => asset.displayStatus === "active").length;
  }, [normalizedAssets]);

  const inactiveCount = useMemo(() => {
    return normalizedAssets.filter((asset) => asset.displayStatus !== "active").length;
  }, [normalizedAssets]);

  const cards = useMemo(
    () => [
      { label: "Total Assets", value: normalizedAssets.length, tone: "primary" },
      { label: "Active Assets", value: activeCount, tone: "success" },
      { label: "Inactive Assets", value: inactiveCount, tone: "warning" },
    ],
    [normalizedAssets.length, activeCount, inactiveCount]
  );

  return (
    <div className="page assets-page">
      <PageHero
        eyebrow="Specula Assets"
        title="Assets Inventory"
        description="Consolidated view of Specula Core, host coverage and connected endpoints."
        badge={`${normalizedAssets.length} assets`}
      />

      <MetricCards items={cards} />

      <PageSection title="Assets List">
        {error ? (
          <p className="error-text">{error}</p>
        ) : !normalizedAssets.length ? (
          <p className="empty-state">No assets found.</p>
        ) : (
          <div className="assets-grid">
            {normalizedAssets.map((asset, index) => (
              <article
                className="asset-card"
                key={asset.asset_id || asset.id || `${asset.displayName}-${index}`}
              >
                <div className="asset-card__top">
                  <div>
                    <div className="asset-title-row">
                      <h3 className="asset-title">{asset.displayName}</h3>
                      {asset.displayRole ? (
                        <span className="asset-badge">{asset.displayRole}</span>
                      ) : null}
                    </div>

                    <p className="asset-subtitle">{asset.displayPlatform}</p>
                  </div>

                  <span className={`asset-status ${getStatusClass(asset.displayStatus)}`}>
                    {asset.displayStatus}
                  </span>
                </div>

                <div className="asset-meta-grid">
                  <div>
                    <span className="asset-label">IP</span>
                    <strong>{asset.ip_address || asset.ip || "-"}</strong>
                  </div>
                  <div>
                    <span className="asset-label">Type</span>
                    <strong>{asset.displayType}</strong>
                  </div>
                  <div>
                    <span className="asset-label">Manager</span>
                    <strong>{asset.displayManager}</strong>
                  </div>
                  <div>
                    <span className="asset-label">Last seen</span>
                    <strong>{asset.displayLastSeen}</strong>
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