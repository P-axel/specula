import { useEffect, useState } from "react";
import { getEvents } from "../../../api/events.api";
import PageSection from "../../../shared/ui/PageSection";

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

  return (
    <div className="page">
      <PageSection title="Events">
        {error ? (
          <p className="error-text">{error}</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, index) => (
                  <tr key={event.id || index}>
                    <td>{event.name || event.message || "-"}</td>
                    <td>{event.source || "-"}</td>
                    <td>{event.severity || event.level || "-"}</td>
                    <td>{event.timestamp || "-"}</td>
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