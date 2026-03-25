import React from "react";

export default function IncidentFilters({ filters, setFilters, onReset }) {
  return (
    <div className="incidents-filters">
      <div className="incidents-filter-group incidents-filter-group--search">
        <label className="incidents-filter-label" htmlFor="incident-search">
          Recherche
        </label>
        <input
          id="incident-search"
          className="incidents-filter-input"
          type="text"
          placeholder="Titre, actif, type, CVE, process, utilisateur, URL, DNS, SNI..."
          value={filters.search}
          onChange={(event) =>
            setFilters((prev) => ({ ...prev, search: event.target.value }))
          }
        />
      </div>

      <div className="incidents-filter-group">
        <label className="incidents-filter-label" htmlFor="incident-kind">
          Famille
        </label>
        <select
          id="incident-kind"
          className="incidents-filter-select"
          value={filters.kind}
          onChange={(event) =>
            setFilters((prev) => ({ ...prev, kind: event.target.value }))
          }
        >
          <option value="all">Toutes</option>
          <option value="network">Réseau</option>
          <option value="system">Système</option>
          <option value="identity">Identité</option>
          <option value="application">Application</option>
          <option value="vulnerability">Vulnérabilité</option>
          <option value="correlated">Corrélé</option>
        </select>
      </div>

      <div className="incidents-filter-group">
        <label className="incidents-filter-label" htmlFor="incident-severity">
          Sévérité
        </label>
        <select
          id="incident-severity"
          className="incidents-filter-select"
          value={filters.severity}
          onChange={(event) =>
            setFilters((prev) => ({ ...prev, severity: event.target.value }))
          }
        >
          <option value="all">Toutes</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      <div className="incidents-filter-group">
        <label className="incidents-filter-label" htmlFor="incident-status">
          Statut
        </label>
        <select
          id="incident-status"
          className="incidents-filter-select"
          value={filters.status}
          onChange={(event) =>
            setFilters((prev) => ({ ...prev, status: event.target.value }))
          }
        >
          <option value="all">Tous</option>
          <option value="open">Ouvert</option>
          <option value="investigating">En investigation</option>
          <option value="closed">Clos</option>
        </select>
      </div>

      <div className="incidents-filter-group">
        <label className="incidents-filter-label" htmlFor="incident-age">
          Période
        </label>
        <select
          id="incident-age"
          className="incidents-filter-select"
          value={filters.age}
          onChange={(event) =>
            setFilters((prev) => ({ ...prev, age: event.target.value }))
          }
        >
          <option value="all">Toute période</option>
          <option value="24h">24 dernières heures</option>
          <option value="7d">7 derniers jours</option>
          <option value="30d">30 derniers jours</option>
        </select>
      </div>

      <div className="incidents-filters__actions">
        <button type="button" className="incidents-filter-reset" onClick={onReset}>
          Réinitialiser
        </button>
      </div>
    </div>
  );
}