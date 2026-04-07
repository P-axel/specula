/**
 * Toast de notification pour les incidents critiques en temps réel.
 * Affiché dans le coin en bas à droite, disparaît après 8 secondes.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useIncidentNotifications } from "../hooks/useIncidentNotifications";

const AUTO_DISMISS_MS = 8000;

export default function CriticalAlertToast() {
  const [toasts, setToasts] = useState([]);
  const counterRef = useRef(0);

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const handleCriticalIncident = useCallback((payload) => {
    const id = ++counterRef.current;
    const toast = {
      id,
      title: payload.title || "Incident critique détecté",
      severity: payload.severity || "critical",
      src_ip: payload.src_ip || null,
      dest_ip: payload.dest_ip || null,
    };
    setToasts((prev) => [...prev.slice(-4), toast]); // max 5 toasts
    setTimeout(() => dismissToast(id), AUTO_DISMISS_MS);
  }, [dismissToast]);

  useIncidentNotifications({ onCriticalIncident: handleCriticalIncident });

  if (!toasts.length) return null;

  return (
    <div className="toast-container" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast toast--${toast.severity}`}>
          <div className="toast__icon">⚠</div>
          <div className="toast__body">
            <div className="toast__title">{toast.title}</div>
            {(toast.src_ip || toast.dest_ip) && (
              <div className="toast__meta">
                {toast.src_ip && <span>{toast.src_ip}</span>}
                {toast.src_ip && toast.dest_ip && <span> → </span>}
                {toast.dest_ip && <span>{toast.dest_ip}</span>}
              </div>
            )}
          </div>
          <button
            type="button"
            className="toast__close"
            onClick={() => dismissToast(toast.id)}
            aria-label="Fermer"
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
