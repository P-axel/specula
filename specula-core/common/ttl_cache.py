"""
Cache in-memory avec TTL et stale-while-revalidate — thread-safe.

Règles de priorité :
  1. Données fraîches (< TTL)         → retour immédiat
  2. Données périmées (< stale_ttl)   → retour immédiat + refresh fond silencieux
  3. Aucune donnée disponible         → fetch bloquant (premier démarrage uniquement)

Principe cardinal : un résultat vide ne remplace JAMAIS des données existantes.
L'UI a toujours quelque chose à afficher.
"""
import logging
import threading
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


class TTLCache:
    def __init__(self, ttl: float = 300.0, stale_ttl: float = 3600.0):
        self._ttl       = ttl        # fraîcheur : données servies telles quelles
        self._stale_ttl = stale_ttl  # périmé mais utilisable + refresh fond
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock      = threading.Lock()
        self._inflight: dict[str, threading.Event] = {}
        self._bg_running: set[str] = set()

    # ── API publique ──────────────────────────────────────────────

    def get_or_fetch(self, key: str, fn: Callable[[], Any]) -> Any:
        with self._lock:
            entry = self._store.get(key)
            now   = time.monotonic()

            if entry:
                age = now - entry[0]
                if age < self._ttl:
                    return entry[1]                  # fraîches → immédiat

                if age < self._stale_ttl:
                    self._start_background(key, fn)  # périmées → immédiat + refresh
                    return entry[1]

            # Pas de données → fetch bloquant
            if key in self._inflight:
                evt = self._inflight[key]            # quelqu'un fetche déjà → attend
            else:
                evt = threading.Event()
                self._inflight[key] = evt
                evt = None                           # ce thread fetche

        if evt is not None:
            evt.wait(timeout=60.0)
            with self._lock:
                entry = self._store.get(key)
                return entry[1] if entry else []

        return self._fetch_and_store(key, fn, release_inflight=True)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    # ── Interne ───────────────────────────────────────────────────

    def _start_background(self, key: str, fn: Callable[[], Any]) -> None:
        """Lance un refresh fond si aucun n'est déjà en cours pour cette clé."""
        if key in self._bg_running or key in self._inflight:
            return
        self._bg_running.add(key)
        t = threading.Thread(
            target=self._bg_fetch,
            args=(key, fn),
            daemon=True,
        )
        t.start()

    def _bg_fetch(self, key: str, fn: Callable[[], Any]) -> None:
        try:
            self._fetch_and_store(key, fn, release_inflight=False)
        finally:
            with self._lock:
                self._bg_running.discard(key)

    def _fetch_and_store(self, key: str, fn: Callable[[], Any], release_inflight: bool) -> Any:
        """
        Exécute fn(), stocke le résultat SI non vide.
        Règle : un résultat vide ne remplace jamais des données existantes.
        Libère toujours l'inflight event si release_inflight=True.
        """
        result = None
        evt_to_set = None

        try:
            result = fn()
        except Exception as e:
            logger.warning("TTLCache '%s' : erreur fetch — %s", key, e)

        with self._lock:
            if result:                                    # non-vide → on sauvegarde
                self._store[key] = (time.monotonic(), result)
            else:                                         # vide → on garde l'existant
                existing = self._store.get(key)
                if existing:
                    result = existing[1]
                    logger.debug("TTLCache '%s' : fetch vide, données existantes conservées", key)
                else:
                    result = []

            if release_inflight:
                evt_to_set = self._inflight.pop(key, None)

        if evt_to_set:                                    # libère les threads en attente
            evt_to_set.set()

        return result
