"""
Auto-triage heuristique — détecte les faux positifs probables sans IA.
Rapide, déterministe, zéro appel réseau.
"""
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _INTERNAL_NETWORKS)
    except ValueError:
        return False


def _age_days(ts: str | None) -> float:
    if not ts:
        return 0
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400
    except Exception:
        return 0


def score_false_positive(incident: dict[str, Any]) -> dict[str, Any]:
    """
    Retourne un score FP (0-100) et les raisons.
    Score >= 70 → suggère faux positif.
    """
    reasons = []
    score = 0

    src_ip  = incident.get("src_ip")
    dest_ip = incident.get("dest_ip")
    signals = incident.get("signals_count", 0) or 1
    last_seen = incident.get("last_seen") or incident.get("last_seen")
    age = _age_days(last_seen)
    engine  = str(incident.get("dominant_engine") or "").lower()
    title   = str(incident.get("title") or "").lower()

    # Source interne → scan ou trafic local
    if _is_internal(src_ip) and _is_internal(dest_ip):
        score += 35
        reasons.append("trafic LAN uniquement")

    # Signal unique → bruit ponctuel
    if signals == 1:
        score += 20
        reasons.append("1 seul signal")
    elif signals <= 3:
        score += 10

    # Vieux et stable (pas de nouveaux signaux récents)
    if age > 14:
        score += 20
        reasons.append(f"inactif depuis {int(age)}j")
    elif age > 7:
        score += 10

    # Patterns connus de faux positifs Suricata/Wazuh
    fp_patterns = [
        ("promiscuous", 25, "mode promiscuité (Suricata attendu)"),
        ("rootcheck", 20, "rootcheck Wazuh (heuristique générique)"),
        ("8.8.8.8", 20, "DNS vers Google (trafic normal)"),
        ("udp port sweep", 15, "UDP sweep sur réseau local"),
    ]
    for pattern, pts, reason in fp_patterns:
        if pattern in title:
            score += pts
            reasons.append(reason)

    score = min(score, 100)
    return {
        "fp_score": score,
        "fp_likely": score >= 70,
        "fp_reasons": reasons,
    }


def triage_incidents(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrichit chaque incident avec le score FP heuristique."""
    result = []
    for inc in incidents:
        triage = score_false_positive(inc)
        result.append({**inc, **triage})
    return result
