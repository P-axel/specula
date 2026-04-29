"""Agent 2 — Corrélation. Sortie JSON uniquement."""
import json, logging
from typing import Any
from ai.ollama_client import chat

logger = logging.getLogger(__name__)

SYSTEM = """You are a threat intelligence analyst. Correlate the incident with related events. Return ONLY valid JSON.

JSON schema:
{
  "is_campaign": boolean,
  "campaign_confidence": float 0-1,
  "pattern_description": string,
  "attacker_persistence": "none"|"low"|"medium"|"high",
  "escalation_trend": "stable"|"escalating"|"decreasing",
  "recommended_scope": "isolated"|"asset"|"network_segment"|"organization"
}"""

def run(incident: dict[str, Any], analyst_output: dict[str, Any], related: list[dict[str, Any]]) -> dict[str, Any]:
    user = (
        f"Incident: {json.dumps(incident, default=str)}\n"
        f"Threat analysis: {json.dumps(analyst_output)}\n"
        f"Related incidents ({len(related)}): {json.dumps(related[:5], default=str)}\n"
        "Return JSON correlation."
    )
    result = chat(SYSTEM, user)
    logger.info("Correlator → campaign=%s scope=%s", result.get("is_campaign"), result.get("recommended_scope"))
    return result
