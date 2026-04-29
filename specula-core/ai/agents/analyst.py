"""Agent 1 — Analyse de menace. Sortie JSON uniquement."""
import json, logging
from typing import Any
from ai.ollama_client import chat

logger = logging.getLogger(__name__)

SYSTEM = """You are a SOC L3 analyst. Analyze the security incident and return ONLY valid JSON.

JSON schema (no extra fields, no markdown):
{
  "threat_type": string,
  "attack_vector": string,
  "real_severity": "critical"|"high"|"medium"|"low",
  "confidence": float 0-1,
  "attacker_objective": string,
  "key_indicators": [string],
  "false_positive_risk": "low"|"medium"|"high"
}"""

def run(incident: dict[str, Any]) -> dict[str, Any]:
    user = f"Incident:\n{json.dumps(incident, default=str)}\n\nReturn JSON analysis."
    result = chat(SYSTEM, user)
    logger.info("Analyst → %s %s", result.get("threat_type"), result.get("real_severity"))
    return result
