import { useEffect, useMemo, useState } from "react";
import { getDetections } from "../../../api/detections.api";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import RecentDetections from "../../dashboard/components/RecentDetections";

export default function DetectionsPage() {
  const [detections, setDetections] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDetections() {
      try {
        const data = await getDetections();
        setDetections(Array.isArray(data) ? data : data.items || []);
      } catch (err) {
        setError(err.message || "Failed to load detections.");
      }
    }

    loadDetections();
  }, []);

  const cards = useMemo(
    () => [
      { label: "Detections", value: detections.length, tone: "info" },
      {
        label: "Informational",
        value: detections.filter((item) =>
          String(item.severity || "").toLowerCase().includes("info")
        ).length,
        tone: "success",
      },
      {
        label: "High Severity",
        value: detections.filter((item) =>
          String(item.severity || "").toLowerCase().includes("high")
        ).length,
        tone: "danger",
      },
    ],
    [detections]
  );

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Detections"
        title="Detection Signals"
        description="Signaux interprétés par Specula à partir des événements et états remontés par les agents."
        badge={`${detections.length} detections`}
      />

      <MetricCards items={cards} />

      <PageSection title="All Detections">
        {error ? (
          <p className="error-text">{error}</p>
        ) : (
          <RecentDetections detections={detections} />
        )}
      </PageSection>
    </div>
  );
}