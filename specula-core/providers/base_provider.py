from __future__ import annotations

from typing import Any, Protocol, List, Dict, Optional


class DetectionProvider(Protocol):
    """
    Contrat standard pour toute source de détection dans Specula.

    Ce protocole définit une interface commune permettant :
    - d'unifier l'accès aux détections (Wazuh, Suricata, futurs modules)
    - de supporter le multi-provider proprement
    - de préparer la scalabilité (pagination, filtres, multi-source)

    Chaque provider (Wazuh, Suricata, etc.) doit implémenter ce contrat.
    """

    name: str  # identifiant unique du provider (ex: "wazuh", "suricata")

    def list_detections(
        self,
        limit: int = 100,
        offset: int = 0,
        source: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retourne une liste de détections normalisées.

        Args:
            limit: nombre maximum de résultats à retourner
            offset: position de départ (pagination)
            source: filtre optionnel (ex: "wazuh", "suricata")
            filters: filtres supplémentaires (ex: severity, category, date, etc.)

        Exemple:
            filters = {
                "severity": "high",
                "category": "network_scan"
            }

        Returns:
            Liste de détections au format canonique Specula
        """
        ...

    def get_status(self) -> Dict[str, Any]:
        """
        Retourne l’état du provider.

        Exemple de retour:
        {
            "status": "healthy",
            "provider": "wazuh",
            "latency_ms": 120,
            "last_success": "2026-04-02T10:00:00Z"
        }

        Returns:
            Dictionnaire décrivant l'état du provider
        """
        ...