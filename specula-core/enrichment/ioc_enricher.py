"""
Enrichissement IoC — sources sans authentification requise + optionnels avec clé.

Sources actives (toujours disponibles, sans clé) :
- Shodan InternetDB : CVEs, ports ouverts, tags (tor/vpn/scanner), CPEs
  → https://internetdb.shodan.io/{ip}

Sources optionnelles (si clé fournie dans .env) :
- ThreatFox  (abuse.ch) : C2, botnet, familles de malwares — ABUSEIPDB_KEY
- URLhaus    (abuse.ch) : URLs et hôtes malveillants    — ABUSEIPDB_KEY

Configuration .env :
    ABUSEIPDB_KEY=votre_clé_abuse.ch   # gratuit sur abuse.ch

Principes :
- Dégradation gracieuse : si une API est inaccessible, l'incident reste affiché sans enrichissement
- Cache in-memory TTL (1h hits / 15min misses)
- IPs privées filtrées (RFC1918)
- Timeout 3s par appel
- Max 3 IPs par incident pour ne pas bloquer le pipeline
"""
from __future__ import annotations

import ipaddress
import logging
import os
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

_ABUSE_KEY      = os.getenv("ABUSEIPDB_KEY", "").strip()   # clé abuse.ch (ThreatFox + URLhaus)
_REQUEST_TIMEOUT = 3                                        # secondes par appel
_CACHE_TTL_HIT   = 3600   # 1h  — résultat positif (IoC connu)
_CACHE_TTL_MISS  = 900    # 15min — IP inconnue (peut changer)
_CACHE_MAX_SIZE  = 1000

# Tags Shodan considérés comme suspects dans un contexte SOC
_SUSPICIOUS_TAGS = {"tor", "vpn", "scanner", "compromised", "malware", "botnet"}

# ── Cache ──────────────────────────────────────────────────────────────────────

_cache: dict[str, tuple[dict, float]] = {}


def _cache_get(key: str) -> dict | None:
    entry = _cache.get(key)
    if entry is None:
        return None
    result, expires_at = entry
    if time.monotonic() < expires_at:
        return result
    del _cache[key]
    return None


def _cache_set(key: str, result: dict, ttl: float) -> None:
    if len(_cache) >= _CACHE_MAX_SIZE:
        oldest = min(_cache, key=lambda k: _cache[k][1])
        del _cache[oldest]
    _cache[key] = (result, time.monotonic() + ttl)


# ── Filtrage IPs privées ───────────────────────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
    )
]

_HEADERS = {"User-Agent": "Specula-SOC/1.0"}


def _is_private(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split(":")[0])
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ── Shodan InternetDB (gratuit, sans clé) ─────────────────────────────────────

def _shodan_internetdb(ip: str) -> dict:
    """
    Interroge Shodan InternetDB pour une IP.
    Retourne CVEs, ports, tags (tor/vpn/scanner...), hostnames.
    """
    key = f"sdb:{ip}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    try:
        resp = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=_REQUEST_TIMEOUT,
            headers=_HEADERS,
        )
        if resp.status_code == 404 or resp.json().get("detail") == "No information available":
            _cache_set(key, {}, _CACHE_TTL_MISS)
            return {}

        resp.raise_for_status()
        data = resp.json()

        vulns    = [v for v in (data.get("vulns") or []) if v]
        tags     = [t for t in (data.get("tags") or []) if t]
        ports    = data.get("ports") or []
        hostnames = data.get("hostnames") or []
        cpes     = data.get("cpes") or []

        suspicious_tags = [t for t in tags if t.lower() in _SUSPICIOUS_TAGS]

        # Pas de data utile → miss court
        if not vulns and not suspicious_tags and not ports:
            _cache_set(key, {}, _CACHE_TTL_MISS)
            return {}

        result = {
            "source": "shodan",
            "vulns": vulns[:10],      # limiter à 10 CVEs pour l'affichage
            "tags": tags,
            "suspicious_tags": suspicious_tags,
            "ports": ports[:15],
            "hostnames": hostnames[:3],
            "cpes": [c.split(":")[-1] for c in cpes[:5] if c],   # nom court seulement
        }
        ttl = _CACHE_TTL_HIT if (vulns or suspicious_tags) else _CACHE_TTL_MISS
        _cache_set(key, result, ttl)
        return result

    except Exception as exc:
        logger.debug("Shodan InternetDB lookup failed for %s: %s", ip, exc)
        return {}


# ── ThreatFox (abuse.ch — clé optionnelle) ────────────────────────────────────

def _threatfox(ioc: str) -> dict:
    """Lookup IP/domaine dans ThreatFox. Requiert ABUSEIPDB_KEY."""
    if not _ABUSE_KEY:
        return {}

    key = f"tf:{ioc}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc},
            timeout=_REQUEST_TIMEOUT,
            headers={**_HEADERS, "Auth-Key": _ABUSE_KEY},
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") == "ok" and data.get("data"):
            hits = data["data"]
            best = max(hits, key=lambda h: h.get("confidence_level", 0))
            result = {
                "source": "threatfox",
                "malware": best.get("malware_printable") or best.get("malware"),
                "threat_type": best.get("threat_type_desc") or best.get("threat_type"),
                "confidence": best.get("confidence_level", 0),
                "first_seen": best.get("first_seen"),
                "last_seen": best.get("last_seen"),
                "count": len(hits),
            }
            _cache_set(key, result, _CACHE_TTL_HIT)
            return result

        _cache_set(key, {}, _CACHE_TTL_MISS)
        return {}
    except Exception as exc:
        logger.debug("ThreatFox lookup failed for %s: %s", ioc, exc)
        return {}


# ── URLhaus (abuse.ch — clé optionnelle) ──────────────────────────────────────

def _urlhaus(host: str) -> dict:
    """Lookup IP/domaine dans URLhaus. Requiert ABUSEIPDB_KEY."""
    if not _ABUSE_KEY:
        return {}

    key = f"uh:{host}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": host},
            timeout=_REQUEST_TIMEOUT,
            headers={**_HEADERS, "Auth-Key": _ABUSE_KEY},
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") == "is_host":
            bls = data.get("blacklists") or {}
            listed = any(v != "not listed" for v in bls.values())
            urls_count = data.get("urls_count", 0)
            result = {
                "source": "urlhaus",
                "urls_count": urls_count,
                "blacklisted": listed,
                "urlhaus_ref": data.get("urlhaus_reference"),
            }
            ttl = _CACHE_TTL_HIT if (urls_count > 0 or listed) else _CACHE_TTL_MISS
            _cache_set(key, result, ttl)
            return result

        _cache_set(key, {}, _CACHE_TTL_MISS)
        return {}
    except Exception as exc:
        logger.debug("URLhaus lookup failed for %s: %s", host, exc)
        return {}


# ── Enrichissement d'un incident ───────────────────────────────────────────────

def enrich_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """
    Enrichit un incident avec la threat intelligence disponible.
    Ne lève jamais d'exception (dégradation gracieuse).

    Résultat attaché à incident["threat_intel"] :
    {
        "hits": [...],
        "reputation_score": 0-100,
        "is_known_bad": bool
    }
    """
    # Collecter les IPs externes à vérifier
    targets: list[tuple[str, str]] = []   # (type, valeur)

    for field in ("dest_ip", "src_ip"):
        val = str(incident.get(field) or "").strip()
        if val and not _is_private(val):
            targets.append(("ip", val))

    for pair in incident.get("ip_pairs") or []:
        if isinstance(pair, dict):
            for k in ("dest", "dest_ip", "src", "src_ip"):
                val = str(pair.get(k) or "").strip()
                if val and not _is_private(val):
                    targets.append(("ip", val))

    raw_host = str(incident.get("http_host") or "").strip().split(":")[0]
    if raw_host and "." in raw_host and not _is_private(raw_host):
        targets.append(("domain", raw_host))

    # Dédoublonner, limiter à 3 cibles
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for t, v in targets:
        if v not in seen:
            seen.add(v)
            deduped.append((t, v))
    deduped = deduped[:3]

    if not deduped:
        return {}

    hits: list[dict] = []

    for kind, val in deduped:
        if kind == "ip":
            # Shodan InternetDB — toujours actif
            sdb = _shodan_internetdb(val)
            if sdb:
                hits.append({"ioc": val, "ioc_type": kind, **sdb})

            # ThreatFox — si clé disponible
            tf = _threatfox(val)
            if tf:
                # Fusionner dans le hit Shodan si déjà présent
                existing = next((h for h in hits if h["ioc"] == val), None)
                if existing:
                    existing.update({k: v2 for k, v2 in tf.items() if k not in existing})
                    existing["source"] = f"{existing.get('source', 'shodan')}+threatfox"
                else:
                    hits.append({"ioc": val, "ioc_type": kind, **tf})

        # URLhaus — domaines et IPs
        uh = _urlhaus(val)
        if uh and (uh.get("urls_count", 0) > 0 or uh.get("blacklisted")):
            existing = next((h for h in hits if h["ioc"] == val), None)
            if existing:
                existing["urlhaus_ref"] = uh.get("urlhaus_ref")
                existing["urls_count"] = uh.get("urls_count", 0)
                existing["source"] = existing.get("source", "") + "+urlhaus"
            else:
                hits.append({"ioc": val, "ioc_type": kind, **uh})

    if not hits:
        return {}

    # Score de réputation global
    reputation_score = 0
    for h in hits:
        # ThreatFox confidence directe
        if h.get("confidence", 0) > reputation_score:
            reputation_score = h["confidence"]
        # Tags suspects → score élevé
        if h.get("suspicious_tags"):
            reputation_score = max(reputation_score, 65)
        # CVEs → score modéré (vulnérable mais pas forcément malveillant)
        if h.get("vulns"):
            reputation_score = max(reputation_score, 40)
        # URLs malveillantes dans URLhaus → très suspect
        if h.get("urls_count", 0) > 0:
            reputation_score = max(reputation_score, 80)

    is_known_bad = (
        reputation_score >= 65
        or any(h.get("urls_count", 0) > 0 for h in hits)
        or any(h.get("blacklisted") for h in hits)
        or any("tor" in (h.get("suspicious_tags") or []) for h in hits)
    )

    return {
        "hits": hits,
        "reputation_score": reputation_score,
        "is_known_bad": is_known_bad,
    }
