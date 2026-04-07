import { useEffect, useMemo, useState } from "react";
import { useSocData } from "../../../shared/providers/SocDataProvider";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";
import MetricCards from "../../../shared/ui/MetricCards";
import "./Incidents.css";

import { DEFAULT_INCIDENT_FILTERS } from "../lib/incidentConstants";
import {
  getPriorityLabel,
  normalizeAlertItem,
  normalizeIncidentItem,
} from "../lib/incidentNormalization";
import {
  extractIncidentSignals,
  filterIncidents,
} from "../lib/incidentFilters";

import IncidentFilters from "../components/IncidentFilters";
import IncidentListItem from "../components/IncidentListItem";
import IncidentDetailPanel from "../components/IncidentDetailPanel";

export default function IncidentsPage() {
  const {
    incidentsRaw = [],
    alertsRaw = [],
    refreshing,
    refreshSocData,
    error,
  } = useSocData();

  const [selectedIncident, setSelectedIncident] = useState(null);
  const [filters, setFilters] = useState({ ...DEFAULT_INCIDENT_FILTERS });

  const incidentsData = useMemo(() => {
    return (Array.isArray(incidentsRaw) ? incidentsRaw : []).map((incident, index) =>
      normalizeIncidentItem(incident, index)
    );
  }, [incidentsRaw]);

  const normalizedAlerts = useMemo(() => {
    return (Array.isArray(alertsRaw) ? alertsRaw : []).map((alert, index) =>
      normalizeAlertItem(alert, index)
    );
  }, [alertsRaw]);

  const highPriorityCount = useMemo(() => {
    return incidentsData.filter((incident) => {
      const priority = getPriorityLabel(incident.severity);
      return priority === "high" || priority === "critical";
    }).length;
  }, [incidentsData]);

  const vulnerabilityCount = useMemo(() => {
    return incidentsData.filter(
      (incident) =>
        incident.kind === "vulnerability" ||
        (Array.isArray(incident.cves) && incident.cves.length > 0)
    ).length;
  }, [incidentsData]);

  const openCount = useMemo(() => {
    return incidentsData.filter((incident) => {
      const status = String(incident.status || "open").toLowerCase();
      return status === "open" || status === "investigating";
    }).length;
  }, [incidentsData]);

  const filteredIncidents = useMemo(() => {
    return filterIncidents(incidentsData, filters);
  }, [incidentsData, filters]);

  useEffect(() => {
    if (!filteredIncidents.length) {
      setSelectedIncident(null);
      return;
    }

    const stillExists = filteredIncidents.some(
      (incident) => incident.id === selectedIncident?.id
    );

    if (!stillExists) {
      setSelectedIncident(filteredIncidents[0]);
    }
  }, [filteredIncidents, selectedIncident]);

  const linkedAlerts = useMemo(() => {
    return extractIncidentSignals(selectedIncident, normalizedAlerts);
  }, [selectedIncident, normalizedAlerts]);

  const cards = useMemo(
    () => [
      {
        label: "Incidents visibles",
        value: incidentsData.length,
        tone: "warning",
      },
      { label: "Incidents ouverts", value: openCount, tone: "info" },
      { label: "Haute priorité", value: highPriorityCount, tone: "danger" },
      {
        label: "Incidents avec CVE",
        value: vulnerabilityCount,
        tone: "info",
      },
    ],
    [incidentsData.length, openCount, highPriorityCount, vulnerabilityCount]
  );

  const heroBadge = useMemo(() => {
    if (!incidentsData.length) return "0 incident";
    if (filteredIncidents.length === incidentsData.length) {
      return `${incidentsData.length} incident(s)`;
    }
    return `${filteredIncidents.length}/${incidentsData.length} incident(s) visibles`;
  }, [filteredIncidents.length, incidentsData.length]);

  const handleResetFilters = () => {
    setFilters({ ...DEFAULT_INCIDENT_FILTERS });
  };
  return (
    <div className="page incidents-page">
      <PageHero
        eyebrow="Specula Incidents"
        title="Incidents à traiter"
        description="Vue d’investigation enrichie : corrélation, contexte technique, détails Wazuh utiles et contexte réseau Suricata."
        badge={heroBadge}
      />

      <div
        style={{
          display: "flex",
          justifyContent: "flex-end",
          marginBottom: "16px",
        }}
      >
        <button
          type="button"
          onClick={refreshSocData}
          disabled={refreshing}
          className="incidents-filter-reset"
          style={{ opacity: refreshing ? 0.72 : 1 }}
        >
          {refreshing ? "Actualisation..." : "Rafraîchir les données"}
        </button>
      </div>

      <MetricCards items={cards} />

      <IncidentFilters
        filters={filters}
        setFilters={setFilters}
        onReset={handleResetFilters}
      />

      {error ? (
        <PageSection title="Erreur">
          <p className="error-text">{error}</p>
        </PageSection>
      ) : (
        <div className="incidents-master-detail">
          <PageSection
            title="Incidents corrélés"
            right={
              <span className="incidents-section-hint">
                Sélectionne un incident pour afficher son contexte enrichi
              </span>
            }
          >
            {!filteredIncidents.length ? (
              <p className="empty-state">
                Aucun incident correspondant aux filtres.
              </p>
            ) : (
              <div className="incident-list">
                {filteredIncidents.map((incident, index) => (
                  <IncidentListItem
                    key={incident.id || `${incident.title || "incident"}-${index}`}
                    incident={incident}
                    isSelected={selectedIncident?.id === incident.id}
                    onSelect={setSelectedIncident}
                  />
                ))}
              </div>
            )}
          </PageSection>

          <PageSection
            title="Détail incident"
            right={
              selectedIncident ? (
                <span className="incidents-section-hint">
                  {selectedIncident.detections_count ?? linkedAlerts.length} signal(s)
                </span>
              ) : null
            }
          >
            <IncidentDetailPanel
              incident={selectedIncident}
              linkedAlerts={linkedAlerts}
            />
          </PageSection>
        </div>
      )}
    </div>
  );
}