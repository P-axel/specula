import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { fetchSocIncidents } from "../../api/soc.api";
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

const CACHE_KEY = "specula_soc_cache_v3";
const CACHE_TTL_MS = 5 * 60 * 1000;

let memoryCache = null;

function findFirstArrayDeep(payload, depth = 0) {
  if (depth > 6 || payload == null) return [];

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

function isFresh(timestamp) {
  return Date.now() - timestamp < CACHE_TTL_MS;
}

function readSessionCache() {
  try {
    const raw = sessionStorage.getItem(CACHE_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw);
    if (!parsed?.timestamp || !isFresh(parsed.timestamp)) return null;

    return parsed;
  } catch {
    return null;
  }
}

function writeSessionCache(data) {
  try {
    sessionStorage.setItem(CACHE_KEY, JSON.stringify(data));
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
  const initialCache =
    memoryCache && memoryCache.timestamp && isFresh(memoryCache.timestamp)
      ? memoryCache
      : readSessionCache();

  const boot = initialCache || createEmptyState();

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
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [initialized, setInitialized] = useState(!!initialCache);

  const hasLoadedRef = useRef(!!initialCache);
  const isFetchingRef = useRef(false);

  const applyAllData = useCallback((nextData) => {
    const payload = {
      ...nextData,
      timestamp: Date.now(),
    };

    setIncidentsRaw(payload.incidentsRaw || []);
    setAlertsRaw(payload.alertsRaw || []);
    setAssetsRaw(payload.assetsRaw || []);
    setOverview(payload.overview ?? null);
    setSeverity(payload.severity ?? null);
    setActivity(payload.activity || []);
    setTopAssets(payload.topAssets || []);
    setTopCategories(payload.topCategories || []);
    setDetections(payload.detections || []);

    setInitialized(true);
    hasLoadedRef.current = true;
    memoryCache = payload;
    writeSessionCache(payload);
  }, []);

  const loadSocData = useCallback(
    async ({ silent = false, force = false } = {}) => {
      if ((hasLoadedRef.current || isFetchingRef.current) && !force) {
        return;
      }

      isFetchingRef.current = true;

      if (silent || initialized) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      try {
        const [
          socIncidentsResponse,
          alertsResponse,
          assetsResponse,
          overviewResponse,
          severityResponse,
          activityResponse,
          topAssetsResponse,
          topCategoriesResponse,
          detectionsResponse,
        ] = await Promise.all([
          fetchSocIncidents(100),
          getAlerts(),
          getAssets(),
          getDashboardOverview(),
          getSeverityDistribution(),
          getDashboardActivity(),
          getTopAssets(),
          getTopCategories(),
          getDetections(),
        ]);

    applyAllData({
          incidentsRaw: Array.isArray(socIncidentsResponse)
            ? socIncidentsResponse
            : extractCollection(socIncidentsResponse),
          alertsRaw: extractCollection(alertsResponse),
          assetsRaw: extractCollection(assetsResponse),
          overview: overviewResponse ?? null,
          severity: severityResponse ?? null,
          activity: Array.isArray(activityResponse) ? activityResponse : [],
          topAssets: Array.isArray(topAssetsResponse) ? topAssetsResponse : [],
          topCategories: Array.isArray(topCategoriesResponse) ? topCategoriesResponse : [],
          detections: Array.isArray(detectionsResponse) ? detectionsResponse : [],
        });
      } catch (err) {
        setError(err?.message || "Impossible de charger les données SOC.");
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
      loadSocData();
    }
  }, [loadSocData]);

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

  return <SocDataContext.Provider value={value}>{children}</SocDataContext.Provider>;
}

export function useSocData() {
  const context = useContext(SocDataContext);

  if (!context) {
    throw new Error("useSocData must be used inside SocDataProvider");
  }

  return context;
}