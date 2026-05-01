import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { getSocIncidents } from "../../api/soc.api";
import { getAlerts } from "../../api/alerts.api";
import { getAssets } from "../../api/assets.api";
import {
  getDashboardOverview,
  getSeverityDistribution,
  getDashboardActivity,
  getTopAssets,
  getTopCategories,
} from "../../api/dashboard.api";
import { getDetections } from "../../api/detections.api";

import InitialLoadingScreen from "../ui/InitialLoadingScreen";

const SocDataContext = createContext(null);

const CACHE_KEY    = "specula_soc_cache_v6";
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 min — localStorage persiste cross-session

let memoryCache = null;

function findFirstArrayDeep(payload, depth = 0) {
  if (depth > 8 || payload == null) return [];

  if (Array.isArray(payload)) return payload;
  if (typeof payload !== "object") return [];

  const preferredKeys = [
    "items",
    "alerts",
    "incidents",
    "results",
    "data",
    "rows",
    "entries",
    "records",
    "value",
    "signals",
    "assets",
  ];

  for (const key of preferredKeys) {
    if (Array.isArray(payload[key])) return payload[key];
  }

  for (const key of preferredKeys) {
    if (payload[key] && typeof payload[key] === "object") {
      const nested = findFirstArrayDeep(payload[key], depth + 1);
      if (nested.length) return nested;
    }
  }

  for (const value of Object.values(payload)) {
    if (Array.isArray(value)) return value;
  }

  for (const value of Object.values(payload)) {
    if (value && typeof value === "object") {
      const nested = findFirstArrayDeep(value, depth + 1);
      if (nested.length) return nested;
    }
  }

  return [];
}

function extractCollection(payload) {
  return findFirstArrayDeep(payload);
}

function extractIncidentsCollection(payload) {
  if (!payload) return [];

  if (Array.isArray(payload)) return payload;

  if (Array.isArray(payload?.incidents)) return payload.incidents;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.data)) return payload.data;

  if (Array.isArray(payload?.data?.incidents)) return payload.data.incidents;
  if (Array.isArray(payload?.data?.items)) return payload.data.items;
  if (Array.isArray(payload?.data?.results)) return payload.data.results;

  return extractCollection(payload);
}

function isFresh(timestamp) {
  return Date.now() - timestamp < CACHE_TTL_MS;
}

function readSessionCache() {
  try {
    // localStorage d'abord (persistant), sessionStorage en fallback
    const raw = localStorage.getItem(CACHE_KEY) || sessionStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed?.timestamp) return null;
    // Données périmées mais non nulles = utilisables (stale-while-revalidate côté frontend)
    if (!isFresh(parsed.timestamp) && Date.now() - parsed.timestamp > 60 * 60 * 1000) return null;
    return parsed;
  } catch {
    return null;
  }
}

function writeSessionCache(data) {
  try {
    const serialized = JSON.stringify(data);
    localStorage.setItem(CACHE_KEY, serialized);
    sessionStorage.setItem(CACHE_KEY, serialized);
  } catch {
    // no-op
  }
}

function createEmptyState() {
  return {
    incidentsRaw: [],
    alertsRaw: [],
    assetsRaw: [],
    overview: null,
    severity: null,
    activity: [],
    topAssets: [],
    topCategories: [],
    detections: [],
    timestamp: 0,
  };
}

export function SocDataProvider({ children }) {
  // Charge le cache même périmé — vaut mieux des données d'hier que rien
  const initialCache =
    memoryCache && memoryCache.timestamp && isFresh(memoryCache.timestamp)
      ? memoryCache
      : readSessionCache();

  const boot = initialCache || createEmptyState();
  const isStale = initialCache && !isFresh(initialCache.timestamp);

  const [incidentsRaw, setIncidentsRaw] = useState(boot.incidentsRaw || []);
  const [alertsRaw, setAlertsRaw] = useState(boot.alertsRaw || []);
  const [assetsRaw, setAssetsRaw] = useState(boot.assetsRaw || []);
  const [overview, setOverview] = useState(boot.overview);
  const [severity, setSeverity] = useState(boot.severity);
  const [activity, setActivity] = useState(boot.activity || []);
  const [topAssets, setTopAssets] = useState(boot.topAssets || []);
  const [topCategories, setTopCategories] = useState(boot.topCategories || []);
  const [detections, setDetections] = useState(boot.detections || []);

  const [loading, setLoading] = useState(!initialCache);
  const [refreshing, setRefreshing] = useState(!!isStale);
  const [dataAge, setDataAge] = useState(initialCache?.timestamp || null);
  const [dataVersion, setDataVersion] = useState(0); // incrémenté à chaque fetch réussi → re-anime les charts
  const [error, setError] = useState("");
  const [initialized, setInitialized] = useState(!!initialCache);

  const hasLoadedRef  = useRef(!!initialCache);
  const isFetchingRef = useRef(false);
  const retryTimerRef = useRef(null);

  const applyAllData = useCallback((nextData) => {
    const payload = {
      ...nextData,
      timestamp: Date.now(),
    };

    setIncidentsRaw(Array.isArray(payload.incidentsRaw) ? payload.incidentsRaw : []);
    setAlertsRaw(Array.isArray(payload.alertsRaw) ? payload.alertsRaw : []);
    setAssetsRaw(Array.isArray(payload.assetsRaw) ? payload.assetsRaw : []);
    setOverview(payload.overview ?? null);
    setSeverity(payload.severity ?? null);
    setActivity(Array.isArray(payload.activity) ? payload.activity : []);
    setTopAssets(Array.isArray(payload.topAssets) ? payload.topAssets : []);
    setTopCategories(Array.isArray(payload.topCategories) ? payload.topCategories : []);
    setDetections(Array.isArray(payload.detections) ? payload.detections : []);

    setInitialized(true);
    setDataAge(payload.timestamp);
    setDataVersion(v => v + 1);
    hasLoadedRef.current = true;
    memoryCache = payload;
    writeSessionCache(payload);
  }, []);

  const loadSocData = useCallback(
    async ({ silent = false, force = false } = {}) => {
      if ((hasLoadedRef.current || isFetchingRef.current) && !force) return;

      isFetchingRef.current = true;
      if (silent || initialized) setRefreshing(true);
      else setLoading(true);
      setError("");

      try {
        // ── Phase 1 : données critiques (incidents + détections) ──────
        // On débloque l'UI dès que ces deux-là répondent.
        const [incRes, detRes] = await Promise.allSettled([
          getSocIncidents(100),
          getDetections(),
        ]);

        const nextIncidents = incRes.status === "fulfilled"
          ? extractIncidentsCollection(incRes.value) : [];
        const nextDetections = detRes.status === "fulfilled"
          ? (Array.isArray(detRes.value) ? detRes.value : extractCollection(detRes.value))
          : [];

        // Ne pas écraser les données existantes avec du vide (backend en warmup)
        // Si on a déjà des données (sessionStorage/mémoire) on les garde en attendant
        const hasNewData = nextIncidents.length > 0 || nextDetections.length > 0;
        const hasExistingData = hasLoadedRef.current && incidentsRaw.length > 0;

        if (hasNewData) {
          applyAllData({
            incidentsRaw: nextIncidents.length ? nextIncidents : nextDetections,
            alertsRaw:     [],
            assetsRaw:     [],
            overview:      null,
            severity:      null,
            activity:      [],
            topAssets:     [],
            topCategories: [],
            detections:    nextDetections,
          });
        } else if (!hasExistingData) {
          // Pas de données du tout → marque initialisé quand même pour débloquer l'UI
          setInitialized(true);
          hasLoadedRef.current = true;
        }
        // Si hasExistingData && !hasNewData : garde les données en mémoire, ne fait rien

        // ── Phase 2 : données secondaires en arrière-plan ────────────
        Promise.allSettled([
          getAlerts(),
          getAssets(),
          getDashboardOverview(),
          getSeverityDistribution(),
          getDashboardActivity(),
          getTopAssets(),
          getTopCategories(),
        ]).then(([alertsR, assetsR, overviewR, sevR, actR, taR, tcR]) => {
          const get = (r, fb = []) => r.status === "fulfilled" ? r.value : fb;
          applyAllData({
            incidentsRaw:  nextIncidents.length ? nextIncidents : nextDetections,
            alertsRaw:     extractCollection(get(alertsR)),
            assetsRaw:     extractCollection(get(assetsR)),
            overview:      get(overviewR, null),
            severity:      get(sevR, null),
            activity:      Array.isArray(get(actR)) ? get(actR) : extractCollection(get(actR)),
            topAssets:     Array.isArray(get(taR))  ? get(taR)  : extractCollection(get(taR)),
            topCategories: Array.isArray(get(tcR))  ? get(tcR)  : extractCollection(get(tcR)),
            detections:    nextDetections,
          });
        });

      } catch (err) {
        console.error("loadSocData error", err);
        setError(err?.message || "Impossible de charger les données SOC.");
        // Débloque quand même l'UI — mieux vaut afficher vide que spinner infini
        setInitialized(true);
        hasLoadedRef.current = true;
      } finally {
        isFetchingRef.current = false;
        setLoading(false);
        setRefreshing(false);
      }
    },
    [applyAllData, initialized]
  );

  useEffect(() => {
    if (!hasLoadedRef.current) {
      // Première visite — fetch bloquant
      loadSocData();
    } else if (isStale) {
      // Données stale en localStorage — refresh silencieux immédiat
      loadSocData({ silent: true, force: true });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Retry automatique si les données restent vides après 20s (backend en warmup)
  useEffect(() => {
    if (initialized && incidentsRaw.length === 0 && !isFetchingRef.current) {
      if (retryTimerRef.current) clearTimeout(retryTimerRef.current);
      retryTimerRef.current = setTimeout(() => {
        loadSocData({ silent: true, force: true });
      }, 20_000);
    } else {
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
    }
    return () => { if (retryTimerRef.current) clearTimeout(retryTimerRef.current); };
  }, [initialized, incidentsRaw.length, loadSocData]);

  const value = useMemo(
    () => ({
      incidentsRaw,
      alertsRaw,
      assetsRaw,
      overview,
      severity,
      activity,
      topAssets,
      topCategories,
      detections,
      loading,
      refreshing,
      dataAge,
      dataVersion,
      error,
      initialized,
      reloadSocData: () => loadSocData({ force: true }),
      refreshSocData: () => loadSocData({ silent: true, force: true }),
    }),
    [
      incidentsRaw,
      alertsRaw,
      assetsRaw,
      overview,
      severity,
      activity,
      topAssets,
      topCategories,
      detections,
      loading,
      refreshing,
      error,
      initialized,
      loadSocData,
    ]
  );

  if (!initialized && loading) {
    return <InitialLoadingScreen />;
  }

  return (
    <SocDataContext.Provider value={value}>
      {children}
    </SocDataContext.Provider>
  );
}

export function useSocData() {
  const context = useContext(SocDataContext);

  if (!context) {
    throw new Error("useSocData must be used inside SocDataProvider");
  }

  return context;
}