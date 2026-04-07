"""
Enrichissement GeoIP léger pour Specula.

Utilise la base GeoLite2-City de MaxMind si disponible
(téléchargeable gratuitement avec compte MaxMind).

Si la base est absente, retourne None sans lever d'exception
(le système continue de fonctionner normalement).

Chemin base par défaut : /opt/specula/GeoLite2-City.mmdb
ou via SPECULA_GEOIP_DB_PATH dans .env
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_GEOIP_PATH = Path(
    os.getenv("SPECULA_GEOIP_DB_PATH", "/opt/specula/GeoLite2-City.mmdb")
)

_reader: Any = None
_available: bool | None = None


def _get_reader() -> Any:
    global _reader, _available

    if _available is False:
        return None

    if _reader is not None:
        return _reader

    try:
        import geoip2.database  # type: ignore
        _reader = geoip2.database.Reader(str(_GEOIP_PATH))
        _available = True
        return _reader
    except ImportError:
        _available = False
        return None
    except FileNotFoundError:
        _available = False
        return None
    except Exception:
        _available = False
        return None


def lookup(ip: str | None) -> dict[str, Any] | None:
    """
    Retourne les informations géographiques pour une IP.

    Returns:
        dict avec country_code, country_name, city, latitude, longitude
        ou None si non disponible / IP privée / erreur
    """
    if not ip:
        return None

    # Ignorer les IPs privées
    try:
        from ipaddress import ip_address as parse_ip
        parsed = parse_ip(ip)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return None
    except ValueError:
        return None

    reader = _get_reader()
    if reader is None:
        return None

    try:
        response = reader.city(ip)
        return {
            "country_code": response.country.iso_code,
            "country_name": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }
    except Exception:
        return None


def is_available() -> bool:
    """Retourne True si la base GeoIP est disponible."""
    return _get_reader() is not None
