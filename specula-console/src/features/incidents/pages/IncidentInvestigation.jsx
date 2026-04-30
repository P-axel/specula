/**
 * IncidentInvestigation — page d'investigation dédiée /incidents/:id
 *
 * 2 colonnes :
 *  gauche  : contexte technique (flux réseau, description, métadonnées, signaux)
 *  droite  : action & enrichissement (statut, threat intel, MITRE, recommandations,
 *             pièces jointes, notes, historique)
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useParams, useLocation, useNavigate } from "react-router-dom";
import {
  PriorityBadge,
  IncidentEngineBadge,
  IncidentKindBadge,
} from "../components/IncidentBadges";
import {
  useIncidentStore,
  saveStatusTransition,
} from "../hooks/useIncidentStore";
import "./IncidentInvestigation.css";

/* ── Constantes ───────────────────────────────────────────────────────────── */

const SEV_COLORS = {
  critical: "#ff2244",
  high:     "#ff6b00",
  medium:   "#ffaa00",
  low:      "#4fb8ff",
  info:     "#183f58",
};

const STATUS_OPTIONS = [
  { value: "open",           label: "Ouvert",       color: "#ff2244" },
  { value: "investigating",  label: "En cours",     color: "#ffaa00" },
  { value: "resolved",       label: "Résolu",       color: "#39ff14" },
  { value: "false_positive", label: "Faux positif", color: "#6899b4" },
];

/* ── Recommandations générées depuis les données de l'incident ─────────────── */
function buildRecommendations(incident) {
  const recs = [];
  const sev    = String(incident.severity || "info").toLowerCase();
  const kind   = String(incident.kind || incident.incident_domain || "").toLowerCase();
  const mitre  = incident.mitre ?? {};
  const ti     = incident.threat_intel ?? null;
  const status = String(incident.status || "open").toLowerCase();

  if (status === "open" && (sev === "critical" || sev === "high")) {
    recs.push({ icon: "⚡", text: "Priorité haute — prendre en charge immédiatement." });
  }
  if (ti?.is_known_bad) {
    recs.push({ icon: "🚫", text: `IP connue malveillante (score ${ti.reputation_score}/100) — bloquer en pare-feu et isoler le poste source.` });
  }
  if (Array.isArray(ti?.hits)) {
    const vulnHit = ti.hits.find((h) => h.vulns?.length > 0);
    if (vulnHit) {
      recs.push({ icon: "🔧", text: `CVEs détectées sur l'IP : appliquer les patches disponibles (${vulnHit.vulns.slice(0, 3).join(", ")}…).` });
    }
  }
  if (kind === "network" || incident.src_ip) {
    recs.push({ icon: "🔍", text: "Vérifier les logs Suricata pour d'autres alertes sur les mêmes IPs sur les 24 dernières heures." });
  }
  if (kind.includes("dns") || String(incident.title || "").toLowerCase().includes("dns")) {
    recs.push({ icon: "🌐", text: "Analyser les requêtes DNS anormales — possible DGA ou tunneling DNS. Bloquer le domaine si confirmé." });
  }
  if (mitre.tactic === "execution" || mitre.tactic === "persistence") {
    recs.push({ icon: "🛡", text: "Tactique MITRE persistance/exécution détectée — vérifier les clés de registre, tâches planifiées et services nouveaux." });
  }
  if (mitre.tactic === "lateral-movement" || mitre.tactic === "credential-access") {
    recs.push({ icon: "🔐", text: "Mouvement latéral ou vol de credentials potentiel — réinitialiser les mots de passe des comptes exposés et auditer les connexions." });
  }
  if (kind === "vulnerability" || kind.includes("vuln")) {
    recs.push({ icon: "📋", text: "Documenter la CVE concernée, vérifier le score CVSS et prioriser le patch dans le plan de remédiation." });
  }
  if (kind === "system") {
    recs.push({ icon: "🖥", text: "Vérifier l'intégrité du système (Wazuh FIM) et les processus actifs suspects via Wazuh agent." });
  }
  if (recs.length === 0) {
    recs.push({ icon: "📄", text: "Analyser les signaux liés et documenter vos conclusions dans les notes d'investigation." });
  }
  return recs;
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */

function formatTs(ts) {
  if (!ts) return null;
  try {
    return new Date(ts).toLocaleString("fr-FR", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return ts; }
}

function formatAge(ts) {
  if (!ts) return null;
  const ms = Date.now() - new Date(ts).getTime();
  if (ms < 0) return null;
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  if (h >= 24) return `${Math.floor(h / 24)}j ${h % 24}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatSize(bytes) {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(1)} Mo`;
}

function cleanTitle(title, asset) {
  if (!title) return "Incident sans titre";
  if (asset && title.endsWith(`(${asset})`)) return title.slice(0, -(asset.length + 3)).trim();
  return title;
}

/* ── Dropdown statut ──────────────────────────────────────────────────────── */
function StatusDropdown({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const current = STATUS_OPTIONS.find((o) => o.value === value) ?? STATUS_OPTIONS[0];

  useEffect(() => {
    function onClickOut(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOut);
    return () => document.removeEventListener("mousedown", onClickOut);
  }, []);

  return (
    <div className="inv-status-dropdown" ref={ref}>
      <button
        type="button"
        className="inv-status-trigger"
        style={{ "--status-color": current.color }}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="inv-status-dot" style={{ background: current.color }} />
        {current.label}
        <span className="inv-status-chevron">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="inv-status-menu">
          {STATUS_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              className={`inv-status-option${opt.value === value ? " is-active" : ""}`}
              style={{ "--status-color": opt.color }}
              onClick={() => { onChange(opt.value); setOpen(false); }}
            >
              <span className="inv-status-dot" style={{ background: opt.color }} />
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────────────── */

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

const SEV_AI = { critical: "#ff2244", high: "#ff6b00", medium: "#ffaa00", low: "#4fb8ff" };

function AiReportView({ report }) {
  const a = report.analyst      ?? {};
  const c = report.correlator   ?? {};
  const r = report.remediation  ?? {};
  const score = r.risk_score ?? null;

  return (
    <div className="ai-report">
      <div className="ai-report__meta">
        <span className="ai-report__model">{report.model}</span>
        <span className="ai-report__duration">{report.duration_s}s</span>
      </div>

      {/* Score global */}
      {score !== null && (
        <div className="ai-score" style={{ "--score-color": score >= 75 ? "#ff2244" : score >= 50 ? "#ff6b00" : "#ffaa00" }}>
          <span className="ai-score__val">{score}</span>
          <span className="ai-score__label">/100 — risque calculé</span>
        </div>
      )}

      {/* Analyse menace */}
      <div className="ai-section">
        <div className="ai-section__title">Menace identifiée</div>
        <div className="ai-threat">
          <span className="ai-tag">{a.threat_type}</span>
          <span className="ai-tag ai-tag--vector">{a.attack_vector}</span>
          {a.real_severity && (
            <span className="ai-tag" style={{ color: SEV_AI[a.real_severity] ?? "#cce4f4" }}>
              {a.real_severity}
            </span>
          )}
          {a.confidence !== undefined && (
            <span className="ai-tag ai-tag--conf">conf. {Math.round(a.confidence * 100)}%</span>
          )}
        </div>
        {a.attacker_objective && <p className="ai-text">{a.attacker_objective}</p>}
        {a.key_indicators?.length > 0 && (
          <ul className="ai-list">
            {a.key_indicators.map((k, i) => <li key={i}>{k}</li>)}
          </ul>
        )}
        {a.false_positive_risk && (
          <p className="ai-fp">Risque faux positif : <strong>{a.false_positive_risk}</strong></p>
        )}
      </div>

      {/* Corrélation */}
      <div className="ai-section">
        <div className="ai-section__title">Corrélation</div>
        <div className="ai-threat">
          {c.is_campaign && <span className="ai-tag ai-tag--alert">Campagne détectée</span>}
          <span className="ai-tag">{c.recommended_scope}</span>
          <span className="ai-tag">{c.attacker_persistence} persistence</span>
          <span className="ai-tag">{c.escalation_trend}</span>
        </div>
        {c.pattern_description && <p className="ai-text">{c.pattern_description}</p>}
      </div>

      {/* Remédiation */}
      <div className="ai-section">
        <div className="ai-section__title">Actions immédiates</div>
        <ol className="ai-actions">
          {(r.immediate_actions ?? []).map((a, i) => (
            <li key={i} className="ai-action">
              <span className="ai-action__text">{a.action}</span>
              {a.rationale && <span className="ai-action__why">{a.rationale}</span>}
            </li>
          ))}
        </ol>
      </div>

      {(r.short_term_actions ?? []).length > 0 && (
        <div className="ai-section">
          <div className="ai-section__title">Court terme</div>
          <ol className="ai-actions ai-actions--secondary">
            {r.short_term_actions.map((a, i) => (
              <li key={i} className="ai-action">{a.action}</li>
            ))}
          </ol>
        </div>
      )}

      {r.escalate_to_management && (
        <div className="ai-escalate">
          Escalade recommandée — {r.escalation_reason}
        </div>
      )}

      {r.containment_summary && (
        <div className="ai-section">
          <div className="ai-section__title">Synthèse</div>
          <p className="ai-text ai-text--summary">{r.containment_summary}</p>
        </div>
      )}
    </div>
  );
}

export default function IncidentInvestigation() {
  const { id }       = useParams();
  const location     = useLocation();
  const navigate     = useNavigate();
  const fileInputRef = useRef(null);

  const [incident, setIncident] = useState(location.state?.incident ?? null);
  const [status,   setStatus]   = useState(incident?.status ?? "open");
  const [noteText, setNoteText] = useState("");

  const [aiData,    setAiData]    = useState(null);
  const [aiStarting, setAiStarting] = useState(false);
  const aiPollRef = useRef(null);

  const stopAiPoll = () => { if (aiPollRef.current) { clearInterval(aiPollRef.current); aiPollRef.current = null; } };

  const fetchAiStatus = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/v1/incidents/${id}/analyse`);
      if (!r.ok) return;
      const d = await r.json();
      setAiData(d);
      if (d.status === "done" || d.status === "error" || d.status === "none") stopAiPoll();
    } catch { stopAiPoll(); }
  }, [id]);

  // Charge l'analyse existante à l'ouverture
  useEffect(() => {
    fetchAiStatus();
    return stopAiPoll;
  }, [fetchAiStatus]);

  const handleAiAnalyse = async () => {
    setAiStarting(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/incidents/${id}/analyse`, { method: "POST" });
      const d = await res.json();
      if (res.status === 503) { setAiData({ status: "error", error: "Ollama non actif — lance avec l'option [3]." }); return; }
      setAiData(d);
      if (d.status === "running" || d.status === "pending") {
        aiPollRef.current = setInterval(fetchAiStatus, 3000);
      }
    } catch { setAiData({ status: "error", error: "Backend inaccessible." }); }
    finally { setAiStarting(false); }
  };

  const aiStatus   = aiData?.status ?? "none";
  const aiReport   = aiData?.report ?? null;
  const aiRunning  = aiStatus === "running" || aiStatus === "pending";
  const aiDone     = aiStatus === "done";
  const aiError    = aiStatus === "error" ? (aiData?.error ?? "Erreur analyse.") : null;

  const {
    comments, attachments, statusHistory, loading,
    addComment, deleteComment,
    addAttachment, deleteAttachment, downloadAttachment,
  } = useIncidentStore(id);

  useEffect(() => {
    if (!incident) navigate("/incidents", { replace: true });
  }, [incident, navigate]);

  if (!incident) return null;

  const sev      = String(incident.severity || "info").toLowerCase();
  const sevColor = SEV_COLORS[sev] || SEV_COLORS.info;
  const title    = cleanTitle(incident.title || incident.name, incident.asset_name);
  const age      = formatAge(incident.first_seen || incident.timestamp);
  const score    = incident.risk_score ?? null;
  const isNetwork = incident.kind === "network" || incident.incident_domain === "network";
  const ti       = incident.threat_intel ?? null;
  const mitre    = incident.mitre ?? {};
  const engines  = Array.isArray(incident.engines) ? incident.engines.filter(Boolean) : [];
  const recos    = buildRecommendations({ ...incident, status });

  const handleStatusChange = async (newStatus) => {
    if (newStatus === status) return;
    const old = status;
    setStatus(newStatus);
    await saveStatusTransition(incident.id, old, newStatus);
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!noteText.trim()) return;
    await addComment(noteText);
    setNoteText("");
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) addAttachment(file);
    e.target.value = "";
  };

  return (
    <div className="inv-page" style={{ "--sev-color": sevColor }}>

      {/* ── Header ── */}
      <div className="inv-header">
        <button type="button" className="inv-back-btn" onClick={() => navigate("/incidents")}>
          ← Incidents
        </button>
        <div className="inv-header__sev-bar" />
        <div className="inv-header__body">
          <div className="inv-header__left">
            <div className="inv-header__kicker">Investigation</div>
            <h1 className="inv-header__title">{title}</h1>
            <div className="inv-header__badges">
              <PriorityBadge value={incident.severity} />
              <IncidentKindBadge kind={incident.kind || incident.incident_domain} />
              <IncidentEngineBadge
                engine={incident.engine || incident.dominant_engine || engines[0] || incident.provider}
              />
            </div>
          </div>
          <div className="inv-header__right">
            {score !== null && (
              <div className="inv-score">
                <span className="inv-score__val">{score}</span>
                <span className="inv-score__sub">/100 risque</span>
              </div>
            )}
            {age && <span className="inv-age">{age}</span>}
          </div>
        </div>
      </div>

      {/* ── Corps 2 colonnes ── */}
      <div className="inv-body">

        {/* ══ Colonne gauche ══ */}
        <div className="inv-col inv-col--left">

          {/* Description */}
          {incident.description && (
            <div className="inv-card">
              <div className="inv-card__header">
                <h2 className="inv-card__title">Description</h2>
              </div>
              <div className="inv-card__body">
                <p className="inv-description">{incident.description}</p>
              </div>
            </div>
          )}

          {/* Flux réseau */}
          {isNetwork && (incident.src_ip || incident.dest_ip) && (
            <div className="inv-card">
              <div className="inv-card__header">
                <h2 className="inv-card__title">Flux réseau</h2>
              </div>
              <div className="inv-card__body">
                <div className="inv-flow">
                  <div className="inv-flow__endpoint">
                    <span className="inv-flow__label">Source</span>
                    <code className="inv-flow__ip">{incident.src_ip || "?"}</code>
                    {incident.src_port && <span className="inv-flow__port">:{incident.src_port}</span>}
                  </div>
                  <div className="inv-flow__mid">
                    <span className="inv-flow__arrow">→</span>
                    {incident.app_proto && (
                      <span className="inv-flow__proto">{incident.app_proto.toUpperCase()}</span>
                    )}
                  </div>
                  <div className="inv-flow__endpoint inv-flow__endpoint--dest">
                    <span className="inv-flow__label">Destination</span>
                    <code className="inv-flow__ip inv-flow__ip--dest">{incident.dest_ip || "?"}</code>
                    {incident.dest_port && <span className="inv-flow__port">:{incident.dest_port}</span>}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Métadonnées */}
          <div className="inv-card">
            <div className="inv-card__header">
              <h2 className="inv-card__title">Détails</h2>
            </div>
            <div className="inv-card__body">
              <div className="inv-meta-grid">
                {incident.asset_name && (
                  <div className="inv-meta-cell">
                    <span className="inv-meta-lbl">Actif</span>
                    <span className="inv-meta-val">{incident.asset_name}</span>
                  </div>
                )}
                {incident.signals_count != null && (
                  <div className="inv-meta-cell">
                    <span className="inv-meta-lbl">Signaux</span>
                    <span className="inv-meta-val">{incident.signals_count}</span>
                  </div>
                )}
                {incident.confidence != null && (
                  <div className="inv-meta-cell">
                    <span className="inv-meta-lbl">Confiance</span>
                    <span className="inv-meta-val">{Math.round(Number(incident.confidence) * 100)}%</span>
                  </div>
                )}
                {incident.first_seen && (
                  <div className="inv-meta-cell">
                    <span className="inv-meta-lbl">Première détection</span>
                    <span className="inv-meta-val">{formatTs(incident.first_seen)}</span>
                  </div>
                )}
                {incident.last_seen && (
                  <div className="inv-meta-cell">
                    <span className="inv-meta-lbl">Dernière détection</span>
                    <span className="inv-meta-val">{formatTs(incident.last_seen)}</span>
                  </div>
                )}
                {!incident.first_seen && incident.timestamp && (
                  <div className="inv-meta-cell">
                    <span className="inv-meta-lbl">Horodatage</span>
                    <span className="inv-meta-val">{formatTs(incident.timestamp)}</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Signaux liés */}
          {Array.isArray(incident.detections) && incident.detections.length > 0 && (
            <div className="inv-card">
              <div className="inv-card__header">
                <h2 className="inv-card__title">Signaux liés</h2>
                <span className="inv-card__count">{incident.detections.length}</span>
              </div>
              <div className="inv-signals">
                {incident.detections.slice(0, 15).map((sig, i) => (
                  <div key={sig.id ?? i} className="inv-signal">
                    <div className="inv-signal__top">
                      <span className="inv-signal__title">{sig.title || sig.name || "Signal"}</span>
                      <span className="inv-signal__ts">{formatTs(sig.timestamp)}</span>
                    </div>
                    {sig.description && <p className="inv-signal__desc">{sig.description}</p>}
                    <div className="inv-signal__meta">
                      {sig.engine && <span>{sig.engine}</span>}
                      {sig.category && <span>{sig.category}</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ══ Colonne droite ══ */}
        <div className="inv-col inv-col--right">

          {/* ── Analyse IA ────────────────────────────────────────── */}
          <div className="inv-card inv-card--ai">
            <div className="inv-card__header inv-card__header--ai">
              <h2 className="inv-card__title">Analyse IA</h2>
              <button
                type="button"
                className={`inv-ai-btn${(aiRunning || aiStarting) ? " inv-ai-btn--loading" : ""}`}
                onClick={handleAiAnalyse}
                disabled={aiRunning || aiStarting}
              >
                {aiStarting ? "Lancement…" : aiRunning ? "En cours…" : aiDone ? "Relancer" : "Lancer l'analyse"}
              </button>
            </div>
            <div className="inv-card__body">
              {aiRunning && (
                <div className="inv-ai-running">
                  <span className="inv-ai-spinner" />
                  Agents en cours d'analyse — résultat automatique dans ~2-3 min…
                </div>
              )}
              {aiError && <p className="inv-ai-error">{aiError}</p>}
              {!aiDone && !aiRunning && !aiError && (
                <p className="inv-ai-hint">
                  IA locale — analyse la menace, évalue le risque réel et génère un plan de remédiation précis (~40s).
                </p>
              )}
              {aiDone && aiReport && <AiReportView report={aiReport} />}
            </div>
          </div>

          {/* Statut — dropdown */}
          <div className="inv-card">
            <div className="inv-card__header">
              <h2 className="inv-card__title">Statut</h2>
            </div>
            <div className="inv-card__body">
              <StatusDropdown value={status} onChange={handleStatusChange} />
            </div>
          </div>

          {/* Threat Intel */}
          {ti && (
            <div className="inv-card">
              <div className="inv-card__header">
                <h2 className="inv-card__title">Threat Intelligence</h2>
                {ti.is_known_bad && (
                  <span className="inv-ti-badge inv-ti-badge--bad">Malveillant</span>
                )}
              </div>
              <div className="inv-card__body">
                <div className="inv-ti-score-row">
                  <span className="inv-ti-score__val">{ti.reputation_score}</span>
                  <span className="inv-ti-score__sub">/100 réputation</span>
                </div>
                <div className="inv-ti-hits">
                  {(ti.hits ?? []).map((hit, i) => (
                    <div key={i} className="inv-ti-hit">
                      <div className="inv-ti-hit__header">
                        <code className="inv-ti-ioc">{hit.ioc}</code>
                        <span className="inv-ti-source">{hit.source}</span>
                      </div>
                      {hit.suspicious_tags?.length > 0 && (
                        <div className="inv-ti-row">
                          <span className="inv-ti-lbl">Tags suspects</span>
                          <span className="inv-ti-val inv-ti-val--bad">{hit.suspicious_tags.join(", ")}</span>
                        </div>
                      )}
                      {hit.malware && (
                        <div className="inv-ti-row">
                          <span className="inv-ti-lbl">Malware</span>
                          <span className="inv-ti-val inv-ti-val--malware">{hit.malware}</span>
                        </div>
                      )}
                      {hit.threat_type && (
                        <div className="inv-ti-row">
                          <span className="inv-ti-lbl">Type</span>
                          <span className="inv-ti-val">{hit.threat_type}</span>
                        </div>
                      )}
                      {hit.ports?.length > 0 && (
                        <div className="inv-ti-row">
                          <span className="inv-ti-lbl">Ports ouverts</span>
                          <span className="inv-ti-val">{hit.ports.slice(0, 10).join(", ")}</span>
                        </div>
                      )}
                      {hit.urls_count > 0 && (
                        <div className="inv-ti-row">
                          <span className="inv-ti-lbl">URLs malveillantes</span>
                          <span className="inv-ti-val inv-ti-val--bad">{hit.urls_count} référencée{hit.urls_count > 1 ? "s" : ""}</span>
                        </div>
                      )}
                      {/* CVEs — liste détaillée */}
                      {hit.vulns?.length > 0 && (
                        <>
                          <div className="inv-ti-row">
                            <span className="inv-ti-lbl">CVEs ({hit.vulns.length})</span>
                          </div>
                          <div className="inv-cve-list">
                            {hit.vulns.slice(0, 10).map((cve) => (
                              <div key={cve} className="inv-cve-row">
                                <span className="inv-cve-id">{cve}</span>
                                <span className="inv-cve-desc">Shodan InternetDB</span>
                              </div>
                            ))}
                            {hit.vulns.length > 10 && (
                              <div className="inv-cve-row">
                                <span className="inv-cve-desc">+{hit.vulns.length - 10} de plus…</span>
                              </div>
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* MITRE ATT&CK */}
          {(mitre.tactic || mitre.technique_id) && (
            <div className="inv-card">
              <div className="inv-card__header">
                <h2 className="inv-card__title">MITRE ATT&CK</h2>
              </div>
              <div className="inv-card__body">
                <div className="inv-mitre">
                  {mitre.tactic && (
                    <div className="inv-mitre__row">
                      <span className="inv-mitre__lbl">Tactique</span>
                      <span className="inv-mitre__val">{mitre.tactic}</span>
                    </div>
                  )}
                  {mitre.technique_id && (
                    <div className="inv-mitre__row">
                      <span className="inv-mitre__lbl">Technique</span>
                      <code className="inv-mitre__id">{mitre.technique_id}</code>
                      {mitre.technique_name && (
                        <span className="inv-mitre__name">{mitre.technique_name}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Recommandations */}
          <div className="inv-card">
            <div className="inv-card__header">
              <h2 className="inv-card__title">Recommandations</h2>
            </div>
            <div className="inv-card__body">
              <div className="inv-reco-list">
                {recos.map((r, i) => (
                  <div key={i} className="inv-reco-item">
                    <span className="inv-reco-icon">{r.icon}</span>
                    <span>{r.text}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Notes */}
          <div className="inv-card">
            <div className="inv-card__header">
              <h2 className="inv-card__title">Notes</h2>
              {comments.length > 0 && (
                <span className="inv-card__count">{comments.length}</span>
              )}
            </div>
            <div className="inv-card__body">
              {loading ? (
                <p className="inv-loading">Chargement…</p>
              ) : (
                <>
                  <form className="inv-note-form" onSubmit={handleAddNote}>
                    <textarea
                      className="inv-note-input"
                      rows={3}
                      placeholder="Ajouter une note d'investigation…"
                      value={noteText}
                      onChange={(e) => setNoteText(e.target.value)}
                    />
                    <button type="submit" className="inv-note-submit" disabled={!noteText.trim()}>
                      Ajouter
                    </button>
                  </form>
                  {comments.length > 0 && (
                    <div className="inv-note-list">
                      {comments.map((c) => (
                        <div key={c.id} className="inv-note-item">
                          <p className="inv-note-text">{c.text}</p>
                          <div className="inv-note-meta">
                            <span>{formatTs(c.created_at)}</span>
                            <button
                              type="button"
                              className="inv-note-delete"
                              onClick={() => deleteComment(c.id)}
                              title="Supprimer"
                            >×</button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {/* Pièces jointes */}
          <div className="inv-card">
            <div className="inv-card__header">
              <h2 className="inv-card__title">Pièces jointes</h2>
              {attachments.length > 0 && (
                <span className="inv-card__count">{attachments.length}</span>
              )}
            </div>
            <div className="inv-card__body">
              <input
                type="file"
                ref={fileInputRef}
                style={{ display: "none" }}
                onChange={handleFileChange}
              />
              <div className="inv-attach-zone">
                <button
                  type="button"
                  className="inv-attach-btn"
                  onClick={() => fileInputRef.current?.click()}
                >
                  + Ajouter un fichier
                </button>
                <span className="inv-attach-hint">max 2 Mo</span>
              </div>
              {attachments.length > 0 && (
                <div className="inv-attach-list">
                  {attachments.map((a) => (
                    <div key={a.id} className="inv-attach-item">
                      <button
                        type="button"
                        className="inv-attach-name"
                        onClick={() => downloadAttachment(a)}
                        title="Télécharger"
                      >
                        {a.name}
                      </button>
                      <span className="inv-attach-size">{formatSize(a.size)}</span>
                      <button
                        type="button"
                        className="inv-attach-del"
                        onClick={() => deleteAttachment(a.id)}
                        title="Supprimer"
                      >×</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Historique statuts */}
          {statusHistory.filter((e) => e.from && e.from !== e.to).length > 0 && (
            <div className="inv-card">
              <div className="inv-card__header">
                <h2 className="inv-card__title">Historique statuts</h2>
              </div>
              <div className="inv-history">
                {statusHistory
                  .filter((e) => e.from && e.from !== e.to)
                  .map((e, i) => (
                    <div key={i} className="inv-history__item">
                      <span className="inv-history__from">{e.from}</span>
                      <span className="inv-history__arrow">→</span>
                      <span className="inv-history__to">{e.to}</span>
                      {e.timestamp && (
                        <span className="inv-history__ts">{formatTs(e.timestamp)}</span>
                      )}
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
