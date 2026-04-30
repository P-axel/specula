import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSocData } from "../../../shared/providers/SocDataProvider";
import "./AssetsPage.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

const SEV_COLOR = { critical: "#ff2244", high: "#ff6b00", medium: "#ffaa00", low: "#4fb8ff" };

function riskColor(score) {
  if (score >= 70) return "#ff2244";
  if (score >= 40) return "#ff6b00";
  if (score >= 10) return "#ffaa00";
  return "#39ff14";
}

function riskLabel(score) {
  if (score >= 70) return "Critique";
  if (score >= 40) return "Élevé";
  if (score >= 10) return "Modéré";
  return "Sain";
}

function formatRelative(ts) {
  if (!ts || ts.startsWith("9999")) return "Toujours actif";
  const ms = Date.now() - new Date(ts).getTime();
  const h = Math.floor(ms / 3_600_000);
  const d = Math.floor(h / 24);
  if (d > 0) return `il y a ${d}j`;
  if (h > 0) return `il y a ${h}h`;
  return "récemment";
}

function normalizeAsset(asset) {
  const name = asset.name || asset.hostname || asset.asset_id;
  const isCore = name === "wazuh.manager" || asset.asset_type === "manager";
  const isHost = name === "specula.agent";
  return {
    ...asset,
    displayName: isCore ? "Specula Core" : isHost ? "Specula Host Agent" : name,
    displayPlatform: asset.os_name || asset.platform || "—",
    displayIP: asset.ip_address || asset.ip || "—",
    displayStatus: String(asset.status || "").toLowerCase(),
    isCore,
    isHost,
  };
}

function AssetCard({ asset, summary, onClick }) {
  const score = summary?.risk_score ?? null;
  const stats = summary?.stats ?? {};
  const active = asset.displayStatus === "active";

  return (
    <article
      className={`asc-card${active ? " asc-card--active" : ""}`}
      onClick={onClick}
      style={{ "--risk-color": score !== null ? riskColor(score) : "var(--c-border)" }}
    >
      <div className="asc-card__risk-bar" />

      <div className="asc-card__header">
        <div>
          <span className={`asc-card__status-dot${active ? " asc-card__status-dot--on" : ""}`} />
          <span className="asc-card__name">{asset.displayName}</span>
        </div>
        {score !== null && (
          <div className="asc-card__score" style={{ color: riskColor(score) }}>
            <span className="asc-card__score-val">{score}</span>
            <span className="asc-card__score-lbl">/100</span>
          </div>
        )}
      </div>

      <div className="asc-card__meta">
        <span>{asset.displayPlatform}</span>
        <span>{asset.displayIP}</span>
      </div>

      {score !== null && (
        <div className="asc-card__risk-label" style={{ color: riskColor(score) }}>
          {riskLabel(score)}
          {stats.open > 0 && (
            <span className="asc-card__inc-badge">{stats.open} incident{stats.open > 1 ? "s" : ""} ouvert{stats.open > 1 ? "s" : ""}</span>
          )}
        </div>
      )}

      {summary?.recent_incidents?.length > 0 && (
        <div className="asc-card__incidents">
          {summary.recent_incidents.slice(0, 3).map((inc) => (
            <div key={inc.incident_id} className="asc-card__inc-row">
              <span
                className="asc-card__inc-dot"
                style={{ background: SEV_COLOR[inc.severity] || "#6899b4" }}
              />
              <span className="asc-card__inc-title">
                {(inc.title || "Incident").replace(/\s*\(.*\)$/, "").slice(0, 48)}
              </span>
              <span className="asc-card__inc-status">{inc.status}</span>
            </div>
          ))}
        </div>
      )}

      <div className="asc-card__footer">
        <span>Dernière activité : {formatRelative(asset.last_seen)}</span>
        <span className="asc-card__cta">Voir →</span>
      </div>
    </article>
  );
}

export default function AssetsPage() {
  const { assetsRaw, incidentsRaw } = useSocData();
  const navigate = useNavigate();
  const [summaries, setSummaries] = useState({});

  const assets = useMemo(() =>
    (assetsRaw || []).map(normalizeAsset).filter(a => !a.isCore),
    [assetsRaw]
  );

  // Actifs "observés" depuis Suricata (IPs dans les incidents sans agent Wazuh)
  const observedIPs = useMemo(() => {
    const knownNames = new Set(assets.flatMap(a => [a.displayName, a.displayIP, a.asset_id]));
    const ipMap = {};
    for (const inc of incidentsRaw || []) {
      const name = inc.asset_name;
      if (!name || knownNames.has(name)) continue;
      if (!ipMap[name]) ipMap[name] = { asset_id: name, displayName: name, displayIP: name, displayPlatform: "Réseau", displayStatus: "observed", last_seen: inc.last_seen };
      else if (inc.last_seen > ipMap[name].last_seen) ipMap[name].last_seen = inc.last_seen;
    }
    return Object.values(ipMap);
  }, [assets, incidentsRaw]);

  // Charge les summaries pour chaque actif
  useEffect(() => {
    const all = [...assets, ...observedIPs];
    all.forEach(asset => {
      const id = encodeURIComponent(asset.asset_id || asset.displayName);
      fetch(`${API_BASE}/assets/${id}/summary`)
        .then(r => r.ok ? r.json() : null)
        .then(d => d && setSummaries(prev => ({ ...prev, [asset.asset_id || asset.displayName]: d })))
        .catch(() => {});
    });
  }, [assets, observedIPs]);

  const totalOpen = Object.values(summaries).reduce((s, d) => s + (d?.stats?.open || 0), 0);

  return (
    <div className="page asc-page">
      <div className="asc-hero">
        <div>
          <div className="asc-hero__eyebrow">Surveillance des actifs</div>
          <h1 className="asc-hero__title">Postes & Endpoints</h1>
          <p className="asc-hero__desc">Vue par machine — incidents actifs, score de risque, historique.</p>
        </div>
        <div className="asc-hero__stats">
          <div className="asc-hero__stat">
            <span className="asc-hero__stat-val">{assets.length}</span>
            <span className="asc-hero__stat-lbl">agents actifs</span>
          </div>
          <div className="asc-hero__stat">
            <span className="asc-hero__stat-val" style={{ color: totalOpen > 0 ? "#ff6b00" : "#39ff14" }}>{totalOpen}</span>
            <span className="asc-hero__stat-lbl">incidents ouverts</span>
          </div>
          <div className="asc-hero__stat">
            <span className="asc-hero__stat-val">{observedIPs.length}</span>
            <span className="asc-hero__stat-lbl">hôtes observés</span>
          </div>
        </div>
      </div>

      {assets.length === 0 && observedIPs.length === 0 && (
        <p className="asc-empty">Aucun actif — démarre Specula avec l'option 2 ou 3 et installe un agent.</p>
      )}

      {assets.length > 0 && (
        <section className="asc-section">
          <h2 className="asc-section__title">Agents Specula</h2>
          <div className="asc-grid">
            {assets.map(asset => (
              <AssetCard
                key={asset.asset_id}
                asset={asset}
                summary={summaries[asset.asset_id]}
                onClick={() => navigate(`/assets/${encodeURIComponent(asset.asset_id)}`)}
              />
            ))}
          </div>
        </section>
      )}

      {observedIPs.length > 0 && (
        <section className="asc-section">
          <h2 className="asc-section__title">Hôtes réseau observés <span className="asc-section__hint">(détectés par Suricata, sans agent)</span></h2>
          <div className="asc-grid">
            {observedIPs.map(asset => (
              <AssetCard
                key={asset.displayName}
                asset={asset}
                summary={summaries[asset.displayName]}
                onClick={() => navigate(`/assets/${encodeURIComponent(asset.displayName)}`)}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
