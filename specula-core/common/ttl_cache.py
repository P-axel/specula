"""
Cache in-memory avec TTL et stale-while-revalidate — thread-safe.

Principe :
- Si les données sont fraîches (< TTL) → retourne immédiatement
- Si les données sont périmées mais disponibles → retourne les ANCIENNES données
  immédiatement ET lance un fetch en arrière-plan (stale-while-revalidate)
- Si aucune donnée disponible → fetch bloquant (premier démarrage)

Garantit que l'UI n'est jamais bloquée par un fetch Wazuh.
"""
import logging
import threading
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


class TTLCache:
    def __init__(self, ttl: float = 300.0, stale_ttl: float = 3600.0):
        self._ttl       = ttl        # fraîcheur maximale
        self._stale_ttl = stale_ttl  # données périmées mais encore utilisables
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock      = threading.Lock()
        self._inflight: dict[str, threading.Event] = {}
        self._bg_refresh: set[str] = set()

    def get_or_fetch(self, key: str, fn: Callable[[], Any]) -> Any:
        with self._lock:
            entry = self._store.get(key)
            now   = time.monotonic()

            if entry:
                age = now - entry[0]
                if age < self._ttl:
                    return entry[1]          # Données fraîches → retour immédiat

                if age < self._stale_ttl:
                    # Données périmées mais utilisables → retour immédiat + refresh fond
                    if key not in self._bg_refresh and key not in self._inflight:
                        self._bg_refresh.add(key)
                        t = threading.Thread(
                            target=self._background_fetch,
                            args=(key, fn),
                            daemon=True,
                        )
                        t.start()
                    return entry[1]

            # Aucune donnée ou trop vieille → fetch bloquant
            if key in self._inflight:
                evt = self._inflight[key]
            else:
                evt = threading.Event()
                self._inflight[key] = evt
                evt = None

        if evt is not None:
            evt.wait(timeout=60.0)
            with self._lock:
                entry = self._store.get(key)
                return entry[1] if entry else []

        # Ce thread est le fetcheur principal
        return self._do_fetch(key, fn, inflight=True)

    def _background_fetch(self, key: str, fn: Callable[[], Any]) -> None:
        try:
            self._do_fetch(key, fn, inflight=False)
        finally:
            with self._lock:
                self._bg_refresh.discard(key)

    def _do_fetch(self, key: str, fn: Callable[[], Any], inflight: bool) -> Any:
        try:
            result = fn()
            if not result:
                # Fetch vide → garde l'ancienne valeur si dispo
                with self._lock:
                    old = self._store.get(key)
                    if old:
                        logger.debug("Cache '%s' : fetch vide, conservation données existantes", key)
                        return old[1]
        except Exception as e:
            logger.warning("Cache '%s' : erreur fetch (%s), conservation données existantes si dispo", key, e)
            with self._lock:
                old = self._store.get(key)
                result = old[1] if old else []

        with self._lock:
            if result:  # Ne sauvegarde que si le résultat est non vide
                self._store[key] = (time.monotonic(), result)
            if inflight:
                done = self._inflight.pop(key, None)
        if inflight and done:
            done.set()

        return result

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)
