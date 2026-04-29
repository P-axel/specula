"""
Cache in-memory avec TTL — thread-safe.
Evite les appels Wazuh/Suricata répétés sur chaque endpoint.
"""
import threading
import time
from typing import Any, Callable


class TTLCache:
    def __init__(self, ttl: float = 30.0):
        self._ttl   = ttl
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock  = threading.Lock()
        self._inflight: dict[str, threading.Event] = {}

    def get_or_fetch(self, key: str, fn: Callable[[], Any]) -> Any:
        with self._lock:
            entry = self._store.get(key)
            if entry and (time.monotonic() - entry[0]) < self._ttl:
                return entry[1]
            # Si un fetch est déjà en cours, attend son résultat
            if key in self._inflight:
                evt = self._inflight[key]
            else:
                evt = threading.Event()
                self._inflight[key] = evt
                evt = None  # ce thread va fetcher

        if evt is not None:
            evt.wait(timeout=self._ttl)
            with self._lock:
                entry = self._store.get(key)
                return entry[1] if entry else []

        # Ce thread fetche
        try:
            result = fn()
        except Exception:
            result = []
        finally:
            with self._lock:
                self._store[key] = (time.monotonic(), result)
                done = self._inflight.pop(key, None)
            if done:
                done.set()

        return result

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)
