import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { getNotificationsConfig, sendTestNotification } from "../../../api/notifications.api.js";
import PageHero from "../../../shared/ui/PageHero";
import PageSection from "../../../shared/ui/PageSection";

export default function NotificationsPage() {
  const [config, setConfig]   = useState(null);
  const [error, setError]     = useState("");
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState("");
  const canvasRef = useRef(null);

  useEffect(() => {
    getNotificationsConfig()
      .then(setConfig)
      .catch(() => setError("Impossible de charger la configuration ntfy."));
  }, []);

  useEffect(() => {
    if (!config?.subscribe_url || !canvasRef.current) return;
    QRCode.toCanvas(canvasRef.current, config.subscribe_url, {
      width: 220,
      margin: 2,
      color: { dark: "#cce4f4", light: "#06131c" },
    });
  }, [config]);

  return (
    <div className="page">
      <PageHero
        eyebrow="Specula — Notifications"
        title="Alertes sur smartphone"
        description="Recevez une notification push dès qu'un incident critique ou high est détecté. Tout reste sur votre réseau — aucune donnée n'est envoyée à l'extérieur."
      />

      <PageSection title="Configuration ntfy">
        {error && <p style={{ color: "#ff6f6f" }}>{error}</p>}

        {config && !config.configured && (
          <div style={{ color: "#ffb07b", lineHeight: 1.7 }}>
            <p>ntfy n'est pas encore configuré.</p>
            <p>Ajoutez dans votre <code>.env</code> :</p>
            <pre style={{ background: "#082030", padding: "12px", borderRadius: "8px", fontSize: "0.85rem" }}>
{`NTFY_TOPIC=specula-$(python3 -c "import secrets; print(secrets.token_hex(8))")
NTFY_BASE_URL=http://specula-ntfy:80
# URL accessible depuis votre téléphone (IP LAN ou via make up --profile ssl) :
NTFY_PUBLIC_URL=http://<IP_SPECULA>:2586`}
            </pre>
            <p>Puis relancez le backend : <code>docker restart specula-backend</code></p>
          </div>
        )}

        {config?.configured && (
          <div style={{ display: "flex", gap: "48px", alignItems: "flex-start", flexWrap: "wrap" }}>
            <div>
              <p style={{ marginBottom: "12px", opacity: 0.8 }}>
                Scannez ce QR code avec l'app <strong>ntfy</strong> (Android / iOS) :
              </p>
              <canvas
                ref={canvasRef}
                style={{ borderRadius: "8px", border: "1px solid #24607e" }}
              />
              <p style={{ marginTop: "8px", fontSize: "0.78rem", opacity: 0.6 }}>
                Topic : <code>{config.topic}</code>
              </p>
              <button
                onClick={async () => {
                  setTesting(true); setTestResult("");
                  try {
                    const r = await sendTestNotification();
                    setTestResult(r.sent ? "Notification envoyée !" : `Échec : ${r.reason}`);
                  } catch { setTestResult("Erreur d'envoi."); }
                  finally { setTesting(false); }
                }}
                disabled={testing}
                style={{
                  marginTop: "12px", padding: "8px 18px", borderRadius: "8px",
                  background: testing ? "#183f58" : "#2160ff", color: "#fff",
                  border: "none", cursor: testing ? "not-allowed" : "pointer",
                  fontWeight: 600, fontSize: "0.85rem",
                }}
              >
                {testing ? "Envoi…" : "Envoyer une notification test"}
              </button>
              {testResult && (
                <p style={{ marginTop: "8px", fontSize: "0.82rem", color: testResult.includes("!") ? "#89e6cb" : "#ff6f6f" }}>
                  {testResult}
                </p>
              )}
            </div>

            <div style={{ flex: 1, minWidth: "260px" }}>
              <h3 style={{ marginBottom: "16px", color: "#cce4f4" }}>Comment s'abonner</h3>
              <ol style={{ lineHeight: 2, paddingLeft: "20px" }}>
                <li>Installer <strong>ntfy</strong> sur votre téléphone (gratuit, open source)</li>
                <li>Ouvrir l'app → appuyer sur <strong>+</strong></li>
                <li>Scanner le QR code ou saisir manuellement :</li>
              </ol>
              <pre style={{ background: "#082030", padding: "10px", borderRadius: "6px", fontSize: "0.82rem", marginTop: "8px" }}>
                {config.subscribe_url}
              </pre>

              <div style={{ marginTop: "20px", padding: "14px", background: "#082030", borderRadius: "8px", borderLeft: "3px solid #00e5ff" }}>
                <strong style={{ color: "#00e5ff" }}>Incidents notifiés</strong>
                <ul style={{ marginTop: "8px", lineHeight: 1.9, paddingLeft: "18px" }}>
                  <li>Sévérité <strong>critical</strong> — priorité urgente (son + vibration)</li>
                  <li>Sévérité <strong>high</strong> — priorité haute</li>
                </ul>
                <p style={{ marginTop: "8px", fontSize: "0.8rem", opacity: 0.7 }}>
                  Medium / Low / Info : silencieux (non notifiés).
                </p>
              </div>

              <div style={{ marginTop: "16px", padding: "12px", background: "#082030", borderRadius: "8px", borderLeft: "3px solid #89e6cb" }}>
                <strong style={{ color: "#89e6cb" }}>Souveraineté</strong>
                <p style={{ marginTop: "6px", fontSize: "0.82rem", lineHeight: 1.6, opacity: 0.85 }}>
                  Le serveur ntfy tourne sur votre machine. Aucune donnée de sécurité
                  ne quitte votre réseau. Le topic UUID est le seul facteur d'accès —
                  ne le partagez qu'aux personnes autorisées.
                </p>
              </div>
            </div>
          </div>
        )}
      </PageSection>
    </div>
  );
}
