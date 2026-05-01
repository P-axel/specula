"""
Analyse IA — appel unique pour minimiser le temps de génération sur CPU.
"""
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from ai import ollama_client

logger = logging.getLogger(__name__)

SYSTEM = """You are a SOC L3 analyst. Analyze this NETWORK security incident and return ONLY compact valid JSON.

Context:
- This is a monitored home/lab network (192.168.0.0/16 range)
- 192.168.1.1 and 192.168.1.254 are internal hosts (admin machines)
- 8.8.8.8 is Google DNS — always legitimate
- Suricata is the network IDS capturing all traffic
- Traffic between internal IPs (.1.x ↔ .1.x) is LAN-only and lower risk
- Single-signal incidents from internal sources are likely false positives

Required JSON (no markdown, no explanation):
{
  "threat_type": string,
  "attack_vector": "network"|"endpoint"|"web"|"email",
  "real_severity": "critical"|"high"|"medium"|"low",
  "confidence": float,
  "false_positive_risk": "low"|"medium"|"high",
  "is_campaign": boolean,
  "attacker_objective": string,
  "risk_score": integer,
  "escalate": boolean,
  "immediate_actions": [{"action": string, "rationale": string}],
  "short_term_actions": [{"action": string}],
  "summary": string
}
Rules: max 3 immediate_actions, max 2 short_term_actions, summary max 2 sentences.
If source and destination are both internal IPs, lower severity accordingly."""


def _build_context(incident: dict[str, Any]) -> str:
    """Construit un contexte minimal pour réduire le temps de génération."""
    fields = {
        "title":      incident.get("title") or incident.get("name"),
        "severity":   incident.get("severity"),
        "source":     incident.get("dominant_engine") or incident.get("source"),
        "asset":      incident.get("asset_name"),
        "src_ip":     incident.get("src_ip"),
        "dest_ip":    incident.get("dest_ip"),
        "dest_port":  incident.get("dest_port"),
        "proto":      incident.get("app_proto"),
        "signals":    incident.get("signals_count") or incident.get("detections_count"),
        "mitre":      incident.get("mitre_tactic"),
        "threat_intel": incident.get("threat_intel"),
    }
    # Supprime les None pour réduire la taille
    return json.dumps({k: v for k, v in fields.items() if v is not None}, default=str)


def run_analysis(
    incident: dict[str, Any],
    related_incidents: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not ollama_client.is_available():
        raise ollama_client.OllamaUnavailableError(
            "Ollama non disponible. Démarrez avec l'option [3]."
        )

    context = _build_context(incident)
    related_count = len(related_incidents or [])

    user = f"Incident: {context}\nRelated incidents last 48h: {related_count}\nReturn JSON analysis."

    started = time.monotonic()
    logger.info("Analyse IA (single-agent) pour %s", incident.get("id"))

    result = ollama_client.chat(SYSTEM, user)

    elapsed = round(time.monotonic() - started, 1)
    logger.info("Analyse terminée en %ss", elapsed)

    # Normalise vers le format attendu par le frontend
    return {
        "incident_id": incident.get("id") or incident.get("incident_id"),
        "analysed_at": datetime.now(timezone.utc).isoformat(),
        "model":       ollama_client.OLLAMA_MODEL,
        "duration_s":  elapsed,
        "analyst": {
            "threat_type":         result.get("threat_type"),
            "attack_vector":       result.get("attack_vector"),
            "real_severity":       result.get("real_severity"),
            "confidence":          result.get("confidence"),
            "attacker_objective":  result.get("attacker_objective"),
            "key_indicators":      [],
            "false_positive_risk": result.get("false_positive_risk"),
        },
        "correlator": {
            "is_campaign":          result.get("is_campaign", False),
            "campaign_confidence":  0.0,
            "pattern_description":  "",
            "attacker_persistence": "unknown",
            "escalation_trend":     "stable",
            "recommended_scope":    "isolated",
        },
        "remediation": {
            "risk_score":                result.get("risk_score"),
            "immediate_actions":         result.get("immediate_actions", []),
            "short_term_actions":        result.get("short_term_actions", []),
            "hardening_recommendations": [],
            "escalate_to_management":    result.get("escalate", False),
            "escalation_reason":         "",
            "containment_summary":       result.get("summary", ""),
        },
    }
