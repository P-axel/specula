from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from providers.base_provider import DetectionProvider


class WazuhProvider(DetectionProvider):
    name = "wazuh"

    def __init__(self, alerts_path: str | Path) -> None:
        self.alerts_path = Path(alerts_path)

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.alerts_path.exists():
            return []

        items: list[dict[str, Any]] = []

        try:
            with self.alerts_path.open("r") as f:
                for line in f:
                    try:
                        raw = json.loads(line.strip())
                    except Exception:
                        continue

                    item = self._normalize_alert(raw)
                    if item:
                        items.append(item)

        except Exception:
            return []

        return items[-limit:] if limit > 0 else items

    def _normalize_alert(self, raw: dict[str, Any]) -> dict[str, Any]:
        rule = raw.get("rule") or {}
        data = raw.get("data") or {}
        agent = raw.get("agent") or {}

        # 🔥 Extraction CVE
        cve_ids = []
        if isinstance(data.get("cve"), str):
            cve_ids.append(data.get("cve"))

        if isinstance(data.get("cves"), list):
            cve_ids.extend(data.get("cves"))

        if isinstance(raw.get("vulnerability"), dict):
            cve = raw["vulnerability"].get("cve")
            if cve:
                cve_ids.append(cve)

        # 🔥 MITRE
        mitre = rule.get("mitre") or {}
        mitre_techniques = []

        if isinstance(mitre, dict):
            mitre_techniques = mitre.get("id") or []

        # 🔥 Package info
        package_name = None
        package_version = None

        if isinstance(raw.get("vulnerability"), dict):
            pkg = raw["vulnerability"].get("package")
            if isinstance(pkg, dict):
                package_name = pkg.get("name")
                package_version = pkg.get("version")

        # 🔥 CVSS
        cvss_score = None
        if isinstance(raw.get("vulnerability"), dict):
            cvss_score = raw["vulnerability"].get("cvss", {}).get("score")

        # 🔥 File path
        file_path = data.get("file")

        # 🔥 Category
        groups = rule.get("groups") or []
        category = "system"

        if "authentication" in groups:
            category = "authentication"
        elif "rootcheck" in groups:
            category = "rootcheck"
        elif "syscheck" in groups:
            category = "file_integrity"
        elif "vulnerability" in groups:
            category = "vulnerability"

        # 🔥 Severity mapping
        level = int(rule.get("level") or 0)

        return {
            "id": raw.get("id"),
            "timestamp": raw.get("timestamp"),
            "engine": "wazuh",
            "source_engine": "wazuh",
            "theme": "system",
            "category": category,
            "title": rule.get("description"),
            "severity": level,
            "priority": level,
            "risk_score": level * 5,  # simple base scoring
            "confidence": None,
            "action": None,
            "asset_name": agent.get("name"),
            "hostname": agent.get("name"),
            "user_name": data.get("user"),
            "process_name": data.get("process"),
            "file_path": file_path,
            "package_name": package_name,
            "package_version": package_version,
            "cvss_score": cvss_score,
            "cve_ids": list(set(cve_ids)),
            "mitre_techniques": mitre_techniques,
            "description": raw.get("full_log"),
            "summary": rule.get("description"),
            "raw": raw,
        }