/**
 * Hook WebSocket pour les notifications d'incidents critiques en temps réel.
 * Se connecte à /ws/incidents et appelle onCriticalIncident() à chaque push.
 *
 * Usage :
 *   useIncidentNotifications({ onCriticalIncident: (payload) => showToast(payload) });
 */
import { useCallback, useEffect, useRef } from "react";

const WS_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000")
    .replace(/^http/, "ws");

const RECONNECT_DELAY_MS = 5000;
const MAX_RECONNECT_ATTEMPTS = 10;

export function useIncidentNotifications({ onCriticalIncident } = {}) {
  const wsRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimerRef = useRef(null);
  const unmountedRef = useRef(false);

  const connect = useCallback(() => {
    if (unmountedRef.current) return;

    const url = `${WS_BASE_URL}/ws/incidents`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectAttemptsRef.current = 0;
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        // Ignorer les messages système (ping, connected)
        if (payload.type === "ping" || payload.type === "connected") return;
        if (onCriticalIncident) onCriticalIncident(payload);
      } catch {
        // ignore malformed messages
      }
    };

    ws.onclose = () => {
      if (unmountedRef.current) return;
      if (reconnectAttemptsRef.current >= MAX_RECONNECT_ATTEMPTS) return;
      reconnectAttemptsRef.current += 1;
      reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [onCriticalIncident]);

  useEffect(() => {
    unmountedRef.current = false;
    connect();

    return () => {
      unmountedRef.current = true;
      clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);
}
