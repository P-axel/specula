"""Agent 3 — Remédiation. Sortie JSON uniquement."""
import json, logging
from typing import Any
from ai.ollama_client import chat

logger = logging.getLogger(__name__)

SYSTEM = """You are an incident responder. Generate a precise remediation plan. Return ONLY valid JSON.

JSON schema:
{
  "risk_score": integer 0-100,
  "immediate_actions": [{"priority": int, "action": string, "rationale": string}],
  "short_term_actions": [{"priority": int, "action": string, "rationale": string}],
  "hardening_recommendations": [{"action": string, "impact": string}],
  "escalate_to_management": boolean,
  "escalation_reason": string,
  "containment_summary": string
}

Rules: max 3 immediate_actions, max 3 short_term_actions, max 2 hardening_recommendations. Be specific."""

def run(incident: dict[str, Any], analyst_output: dict[str, Any], correlator_output: dict[str, Any]) -> dict[str, Any]:
    user = (
        f"Incident: {json.dumps(incident, default=str)}\n"
        f"Threat: {json.dumps(analyst_output)}\n"
        f"Correlation: {json.dumps(correlator_output)}\n"
        "Return JSON remediation plan."
    )
    result = chat(SYSTEM, user)
    logger.info("Remediator → score=%s escalate=%s", result.get("risk_score"), result.get("escalate_to_management"))
    return result
