import { useEffect, useMemo, useState } from "react";
import { getEvents } from "../../../api/events.api";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";

function getEventTone(severity) {
  const value = String(severity || "").toLowerCase();
  if (value.includes("high")) return "high";
  if (value.includes("medium")) return "medium";
  if (value.includes("low")) return "low";
  return "info";
}

export default function EventsPage() {
  const [events, setEvents] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadEvents() {
      try {
        const data = await getEvents();
        setEvents(Array.isArray(data) ? data : data.items || []);
      } catch (err) {
        setError(err.message || "Failed to load events.");
      }
    }

    loadEvents();
  }, []);

  const cards = useMemo(
    () => [
      { label: "Events", value: events.length, tone: "primary" },
      {
        label: "Active Status Events",
        value: events.filter((event) =>
          String(event.title || "").toLowerCase().includes("active")
        ).length,
        tone: "success",
      },
    ],
    [events]
  );

  return (
    <div className="page dashboard-page">
      <PageHero
        eyebrow="Specula Events"
        title="Event Stream"
        description="Flux des événements remontés par les agents et normalisés par Specula."
        badge={`${events.length} events`}
      />

      <MetricCards items={cards} />

      <PageSection title="Recent Events">
        {error ? (
          <p className="error-text">{error}</p>
        ) : !events.length ? (
          <p className="empty-state">No events found.</p>
        ) : (
          <div className="detection-list">
            {events.map((event, index) => (
              <article className="detection-item" key={event.event_id || event.id || index}>
                <div className={`severity-pill ${getEventTone(event.severity)}`}>
                  {event.severity || "info"}
                </div>

                <div className="detection-body">
                  <h3 className="detection-title">
                    {event.title || event.name || "Unknown event"}
                  </h3>

                  <div className="detection-meta">
                    <span>{event.source || "-"}</span>
                    <span>{event.event_type || "-"}</span>
                    <span>{event.occurred_at || event.timestamp || "-"}</span>
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