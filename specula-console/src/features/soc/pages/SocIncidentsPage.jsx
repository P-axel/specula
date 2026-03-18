import React, { useEffect, useMemo, useState } from "react";
import { fetchSocIncidents, fetchSocOverview } from "../../../api/soc.api";
import SocIncidentsTable from "../components/SocIncidentsTable";

function StatCard({ title, value, subtitle }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
      <div className="text-sm text-slate-400">{title}</div>
      <div className="mt-2 text-3xl font-semibold text-slate-100">{value}</div>
      {subtitle ? <div className="mt-2 text-xs text-slate-500">{subtitle}</div> : null}
    </div>
  );
}

function DetailRow({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-slate-800/80 py-3">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="max-w-[65%] text-right text-sm text-slate-200 break-words">
        {value ?? "—"}
      </div>
    </div>
  );
}

function formatArray(value) {
  if (!Array.isArray(value) || value.length === 0) return "—";
  return value.join(", ");
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString("fr-FR");
}

function normalizeOverview(data) {
  return {
    totalIncidents: data?.total_incidents ?? 0,
    openIncidents: data?.open_incidents ?? 0,
    highPriorityIncidents: data?.high_priority_incidents ?? 0,
    maxRiskScore: data?.max_risk_score ?? 0,
    engines: data?.engines ?? [],
    themes: data?.themes ?? [],
    categories: data?.categories ?? [],
    assets: data?.assets ?? [],
    items: Array.isArray(data?.items) ? data.items : [],
  };
}

function normalizeIncidents(data) {
  return {
    count: data?.count ?? 0,
    providers: data?.providers ?? [],
    items: Array.isArray(data?.items) ? data.items : [],
  };
}

function resolveIncidentId(item) {
  return item?.id || item?.incident_id || item?.uuid || item?.key || "";
}

function resolveTitle(item) {
  return (
    item?.title ||
    item?.name ||
    item?.summary ||
    item?.incident_title ||
    item?.theme ||
    "Incident sans titre"
  );
}

export default function SocIncidentsPage() {
  const [overview, setOverview] = useState(() => normalizeOverview({}));
  const [incidents, setIncidents] = useState(() => normalizeIncidents({}));
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const items = useMemo(() => {
    if (incidents.items.length) return incidents.items;
    if (overview.items.length) return overview.items;
    return [];
  }, [incidents.items, overview.items]);

  async function loadData({ silent = false } = {}) {
    try {
      setError("");

      if (silent) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      let overviewResponse = {};
let incidentsResponse = {};

try {
  [overviewResponse, incidentsResponse] = await Promise.all([
    fetchSocOverview(),
    fetchSocIncidents(),
  ]);
} catch (e) {
  console.warn("Overview indisponible, fallback incidents only");

  incidentsResponse = await fetchSocIncidents();
}

      const nextOverview = normalizeOverview(overviewResponse);
      const nextIncidents = normalizeIncidents(incidentsResponse);

      setOverview(nextOverview);
      setIncidents(nextIncidents);

      const mergedItems =
        nextIncidents.items.length > 0 ? nextIncidents.items : nextOverview.items;

      setSelectedIncident((current) => {
        if (!mergedItems.length) return null;
        if (!current) return mergedItems[0];

        const currentId = resolveIncidentId(current);
        return (
          mergedItems.find((item) => resolveIncidentId(item) === currentId) ||
          mergedItems[0]
        );
      });
    } catch (err) {
      setError(err.message || "Erreur lors du chargement des incidents SOC.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-5">
      <section className="rounded-2xl border border-slate-800 bg-slate-950/40 p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-semibold tracking-tight text-slate-100">
              Incidents SOC
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Vue SOC globale orientée priorisation, qualification et investigation,
              sans modifier la page Réseau existante.
            </p>
          </div>

          <button
            type="button"
            onClick={() => loadData({ silent: true })}
            disabled={loading || refreshing}
            className="rounded-xl border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-sm font-medium text-blue-200 transition hover:bg-blue-500/15 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {refreshing ? "Actualisation..." : "Rafraîchir"}
          </button>
        </div>
      </section>

      {error ? (
        <section className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">
          {error}
        </section>
      ) : null}

      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          title="Total incidents"
          value={loading ? "..." : overview.totalIncidents}
          subtitle="Vision consolidée SOC"
        />
        <StatCard
          title="Incidents ouverts"
          value={loading ? "..." : overview.openIncidents}
          subtitle="À traiter ou surveiller"
        />
        <StatCard
          title="Priorité haute"
          value={loading ? "..." : overview.highPriorityIncidents}
          subtitle="Nécessitent une attention rapide"
        />
        <StatCard
          title="Score de risque max"
          value={loading ? "..." : overview.maxRiskScore}
          subtitle="Valeur maximale observée"
        />
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,2fr)_380px]">
        <div className="space-y-4">
          <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
            <div className="mb-4 flex items-center justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-slate-100">
                  Liste des incidents
                </h2>
                <p className="mt-1 text-sm text-slate-400">
                  {loading
                    ? "Chargement des incidents..."
                    : `${items.length} incident(s) affiché(s)`}
                </p>
              </div>
            </div>

            <SocIncidentsTable
              items={items}
              selectedIncidentId={resolveIncidentId(selectedIncident)}
              onSelectIncident={setSelectedIncident}
            />
          </div>
        </div>

        <aside className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
          <h2 className="text-lg font-semibold text-slate-100">
            Panneau d’investigation
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Sélectionne un incident pour afficher les détails de qualification.
          </p>

          {!selectedIncident ? (
            <div className="mt-6 rounded-xl border border-slate-800 bg-slate-900/40 p-4 text-sm text-slate-400">
              Aucun incident sélectionné.
            </div>
          ) : (
            <div className="mt-6 space-y-1">
              <div className="mb-4">
                <div className="text-base font-semibold text-slate-100">
                  {resolveTitle(selectedIncident)}
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  ID: {resolveIncidentId(selectedIncident) || "—"}
                </div>
              </div>

              <DetailRow
                label="Statut"
                value={selectedIncident.status || selectedIncident.state}
              />
              <DetailRow
                label="Priorité"
                value={
                  selectedIncident.priority ||
                  selectedIncident.severity ||
                  selectedIncident.level
                }
              />
              <DetailRow
                label="Score de risque"
                value={
                  selectedIncident.risk_score ??
                  selectedIncident.score ??
                  selectedIncident.max_risk_score
                }
              />
              <DetailRow
                label="Moteur"
                value={
                  selectedIncident.provider ||
                  selectedIncident.engine ||
                  selectedIncident.source
                }
              />
              <DetailRow
                label="Thème"
                value={selectedIncident.theme}
              />
              <DetailRow
                label="Catégorie"
                value={selectedIncident.category}
              />
              <DetailRow
                label="Actifs"
                value={formatArray(selectedIncident.assets)}
              />
              <DetailRow
                label="Créé le"
                value={formatDate(selectedIncident.created_at)}
              />
              <DetailRow
                label="Dernière activité"
                value={formatDate(
                  selectedIncident.updated_at ||
                    selectedIncident.last_seen ||
                    selectedIncident.last_activity_at ||
                    selectedIncident.timestamp
                )}
              />
              <DetailRow
                label="Résumé"
                value={
                  selectedIncident.summary ||
                  selectedIncident.description ||
                  selectedIncident.message
                }
              />
            </div>
          )}
        </aside>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
          <h3 className="text-base font-semibold text-slate-100">Moteurs</h3>
          <p className="mt-2 text-sm text-slate-400">
            {loading ? "..." : formatArray(overview.engines)}
          </p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
          <h3 className="text-base font-semibold text-slate-100">Thèmes</h3>
          <p className="mt-2 text-sm text-slate-400">
            {loading ? "..." : formatArray(overview.themes)}
          </p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
          <h3 className="text-base font-semibold text-slate-100">Catégories</h3>
          <p className="mt-2 text-sm text-slate-400">
            {loading ? "..." : formatArray(overview.categories)}
          </p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
          <h3 className="text-base font-semibold text-slate-100">Actifs</h3>
          <p className="mt-2 text-sm text-slate-400">
            {loading ? "..." : formatArray(overview.assets)}
          </p>
        </div>
      </section>
    </div>
  );
}