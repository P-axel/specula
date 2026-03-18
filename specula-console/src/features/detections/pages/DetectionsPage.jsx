import { useEffect, useMemo, useState } from "react";
import { getDetections } from "../../../api/detections.api";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import RecentDetections from "../../dashboard/components/RecentDetections";

const API_BASE_URL = "http://127.0.0.1:8000";

export default function DetectionsPage() {
  const [viewMode, setViewMode] = useState("signals");
  const [items, setItems] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadItems() {
      setLoading(true);
      setError("");

      try {
        if (viewMode === "signals") {
          const data = await getDetections();
          setItems(Array.isArray(data) ? data : data.items || []);
        } else {
          const response = await fetch(`${API_BASE_URL}/incidents`);
          if (!response.ok) {
            throw new Error(`Failed to load incidents (HTTP ${response.status})`);
          }

          const data = await response.json();
          setItems(Array.isArray(data) ? data : data.items || []);
        }
      } catch (err) {
        setError(err.message || "Failed to load data.");
        setItems([]);
      } finally {
        setLoading(false);
      }
    }

    loadItems();
  }, [viewMode]);

  const cards = useMemo(() => {
    const highCount = items.filter((item) => {
      const severity = String(item.severity || "").toLowerCase();
      return severity.includes("high") || severity.includes("critical");
    }).length;

    const lowInfoCount = items.filter((item) => {
      const severity = String(item.severity || "").toLowerCase();
      return severity.includes("low") || severity.includes("info");
    }).length;

    const totalSignals = viewMode === "incidents"
      ? items.reduce((sum, item) => sum + Number(item.signals_count || 0), 0)
      : items.length;

    return [
      {
        label: viewMode === "incidents" ? "Incidents" : "Detections",
        value: items.length,
        tone: "info",
      },
      {
        label: viewMode === "incidents" ? "Correlated Signals" : "Low / Informational",
        value: viewMode === "incidents" ? totalSignals : lowInfoCount,
        tone: "success",
      },
      {
        label: "High Severity",
        value: highCount,
        tone: "danger",
      },
    ];
  }, [items, viewMode]);

  const pageTitle =
    viewMode === "incidents" ? "Security Incidents" : "Detection Signals";

  const pageDescription =
    viewMode === "incidents"
      ? "Incidents corrélés par Specula à partir de plusieurs signaux de détection liés."
      : "Signaux interprétés par Specula à partir des alertes et événements remontés par Wazuh.";

  const badgeText =
    viewMode === "incidents"
      ? `${items.length} incidents`
      : `${items.length} detections`;

  const normalizedItems = useMemo(() => {
    if (viewMode === "signals") {
      return items;
    }

    return items.map((incident) => ({
      id: incident.id,
      title: incident.title,
      name: incident.name || incident.title,
      description: incident.description,
      severity: incident.severity,
      risk_score: incident.risk_score,
      risk_level: incident.risk_level,
      source: incident.source || "specula",
      asset_id: incident.asset_id,
      asset_name: incident.asset_name,
      hostname: incident.hostname,
      timestamp: incident.updated_at || incident.created_at || incident.timestamp,
      created_at: incident.created_at || incident.timestamp,
      updated_at: incident.updated_at,
      category: incident.category,
      type: incident.type || "incident",
      status: incident.status || "open",
      signals_count: incident.signals_count || 0,
      metadata: {
        ...(incident.metadata || {}),
        signals: incident.signals || [],
      },
    }));
  }, [items, viewMode]);

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Detections"
        title={pageTitle}
        description={pageDescription}
        badge={badgeText}
      />

      <div
        style={{
          display: "flex",
          gap: "0.75rem",
          marginBottom: "1rem",
          alignItems: "center",
        }}
      >
        <button
          type="button"
          onClick={() => setViewMode("signals")}
          className={viewMode === "signals" ? "btn btn-primary" : "btn btn-secondary"}
        >
          Signals
        </button>

        <button
          type="button"
          onClick={() => setViewMode("incidents")}
          className={viewMode === "incidents" ? "btn btn-primary" : "btn btn-secondary"}
        >
          Incidents
        </button>

        <span style={{ opacity: 0.75, fontSize: "0.95rem" }}>
          {loading
            ? "Chargement..."
            : viewMode === "incidents"
            ? `${items.length} incident(s)`
            : `${items.length} signal(s)`}
        </span>
      </div>

      <MetricCards items={cards} />

      <PageSection
        title={viewMode === "incidents" ? "All Incidents" : "All Detections"}
      >
        {error ? (
          <p className="error-text">{error}</p>
        ) : loading ? (
          <p>Chargement des données...</p>
        ) : (
          <RecentDetections detections={normalizedItems} />
        )}
      </PageSection>
    </div>
  );
}