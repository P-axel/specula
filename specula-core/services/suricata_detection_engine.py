from __future__ import annotations

from typing import Any, Dict, List

from services.risk_scoring import RiskScoringService


class SuricataDetectionEngine:
    def __init__(self) -> None:
        self.risk_scoring = RiskScoringService()

    def from_suricata_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        detections: List[Dict[str, Any]] = []

        event_type = str(event.get("event_type") or "").strip().lower()

        alert = event.get("alert")
        if not isinstance(alert, dict):
            alert = {}

        http = event.get("http")
        if not isinstance(http, dict):
            http = {}

        dns = event.get("dns")
        if not isinstance(dns, dict):
            dns = {}

        tls = event.get("tls")
        if not isinstance(tls, dict):
            tls = {}

        anomaly = event.get("anomaly")
        if not isinstance(anomaly, dict):
            anomaly = {}

        flow = event.get("flow")
        if not isinstance(flow, dict):
            flow = {}

        signature = str(
            alert.get("signature")
            or event.get("signature")
            or event.get("title")
            or ""
        ).strip()

        signature_id = (
            alert.get("signature_id")
            or event.get("signature_id")
            or event.get("rule_id")
            or event.get("source_rule_id")
        )

        suricata_severity = (
            alert.get("severity")
            if alert.get("severity") is not None
            else event.get("severity")
        )

        alert_category = str(
            alert.get("category")
            or event.get("alert_category")
            or event.get("category")
            or ""
        ).strip()

        action = (
            alert.get("action")
            if alert.get("action") is not None
            else event.get("action")
        )

        src_ip = event.get("src_ip") or event.get("source_ip")
        dest_ip = event.get("dest_ip") or event.get("destination_ip")
        src_port = event.get("src_port")
        dest_port = event.get("dest_port")
        proto = event.get("proto") or event.get("protocol")
        app_proto = event.get("app_proto")
        timestamp = event.get("timestamp") or event.get("created_at")
        flow_id = event.get("flow_id")
        in_iface = event.get("in_iface")
        direction = event.get("direction")

        hostname = http.get("hostname") or event.get("host") or event.get("hostname")
        url = http.get("url") or event.get("url")
        http_method = http.get("http_method") or event.get("http_method")
        http_status = http.get("status") or event.get("http_status")
        user_agent = (
            http.get("user_agent")
            or http.get("http_user_agent")
            or event.get("user_agent")
        )

        rrname = dns.get("rrname") or event.get("rrname")
        rcode = dns.get("rcode") or event.get("rcode")
        dns_type = dns.get("type") or event.get("dns_type")

        sni = tls.get("sni") or event.get("sni")
        tls_version = tls.get("version") or event.get("tls_version")
        tls_subject = tls.get("subject") or event.get("tls_subject")
        tls_issuerdn = tls.get("issuerdn") or event.get("tls_issuerdn")

        anomaly_type = anomaly.get("type") or event.get("anomaly_type")
        anomaly_event = anomaly.get("event") or event.get("anomaly_event")
        anomaly_layer = anomaly.get("layer") or event.get("anomaly_layer")

        flow_state = flow.get("state") or event.get("flow_state")
        pkts_toserver = flow.get("pkts_toserver") or event.get("pkts_toserver")
        pkts_toclient = flow.get("pkts_toclient") or event.get("pkts_toclient")
        bytes_toserver = flow.get("bytes_toserver") or event.get("bytes_toserver")
        bytes_toclient = flow.get("bytes_toclient") or event.get("bytes_toclient")

        def normalize_suricata_severity(value: Any) -> str:
            if isinstance(value, int):
                return {
                    1: "critical",
                    2: "high",
                    3: "medium",
                    4: "low",
                }.get(value, "low")

            value_str = str(value or "").strip().lower()
            if value_str in {"critical", "high", "medium", "low", "info"}:
                return value_str
            return "low"

        def format_endpoint(ip: Any, port: Any) -> str:
            ip_str = str(ip or "").strip()
            if not ip_str:
                return "unknown"

            port_str = str(port or "").strip()
            if not port_str:
                return ip_str

            if ":" in ip_str:
                return f"[{ip_str}]:{port_str}"
            return f"{ip_str}:{port_str}"

        def endpoint_pair() -> str:
            return f"{format_endpoint(src_ip, src_port)} → {format_endpoint(dest_ip, dest_port)}"

        def signature_text() -> str:
            return signature.lower()

        def dedupe_tags(tags: List[str]) -> List[str]:
            seen: set[str] = set()
            result: List[str] = []

            for tag in tags:
                value = str(tag or "").strip().lower()
                if not value or value in seen:
                    continue
                seen.add(value)
                result.append(value)

            return result

        def build_detection(
            title: str,
            description: str,
            severity: str,
            category: str,
            detection_type: str,
            confidence: float,
            rationale: str,
            recommended_actions: List[str] | None = None,
            asset_criticality: str = "medium",
            extra_tags: List[str] | None = None,
        ) -> Dict[str, Any]:
            tags = dedupe_tags(
                [
                    event_type,
                    app_proto or "",
                    category,
                    *(extra_tags or []),
                ]
            )

            detection = {
                "id": (
                    f"suricata:"
                    f"{signature_id or 'na'}:"
                    f"{flow_id or 'noflow'}:"
                    f"{timestamp or 'notime'}:"
                    f"{src_ip or 'nosrc'}:"
                    f"{dest_ip or 'nodst'}:"
                    f"{dest_port or 'noport'}"
                ),
                "title": title,
                "name": title,
                "description": description,
                "severity": severity,
                "confidence": confidence,
                "source": "suricata",
                "engine": "suricata",
                "source_rule_id": signature_id,
                "rule_id": signature_id,
                "timestamp": timestamp,
                "created_at": timestamp,
                "category": category,
                "type": detection_type,
                "status": "open",
                "asset": dest_ip,
                "asset_name": dest_ip,
                "hostname": hostname or dest_ip,
                "asset_criticality": asset_criticality,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "src_port": src_port,
                "dest_port": dest_port,
                "protocol": proto,
                "proto": proto,
                "app_proto": app_proto,
                "direction": direction,
                "flow_id": flow_id,
                "in_iface": in_iface,
                "action": action,
                "recommended_actions": recommended_actions or [],
                "tags": tags,
                "metadata": {
                    "suricata_event_type": event_type,
                    "suricata_signature": signature,
                    "suricata_signature_id": signature_id,
                    "suricata_category": alert_category,
                    "suricata_severity": suricata_severity,
                    "suricata_action": action,
                    "flow_id": flow_id,
                    "in_iface": in_iface,
                    "hostname": hostname,
                    "url": url,
                    "http_method": http_method,
                    "http_status": http_status,
                    "user_agent": user_agent,
                    "rrname": rrname,
                    "rcode": rcode,
                    "dns_type": dns_type,
                    "sni": sni,
                    "tls_version": tls_version,
                    "tls_subject": tls_subject,
                    "tls_issuerdn": tls_issuerdn,
                    "anomaly_type": anomaly_type,
                    "anomaly_event": anomaly_event,
                    "anomaly_layer": anomaly_layer,
                    "flow_state": flow_state,
                    "pkts_toserver": pkts_toserver,
                    "pkts_toclient": pkts_toclient,
                    "bytes_toserver": bytes_toserver,
                    "bytes_toclient": bytes_toclient,
                    "rationale": rationale,
                },
                "raw": event,
            }

            scored = self.risk_scoring.score_detection(detection)

            if "risk_level" in scored and "priority" not in scored:
                scored["priority"] = scored["risk_level"]

            return scored

        normalized_severity = normalize_suricata_severity(suricata_severity)
        sig = signature_text()
        pair = endpoint_pair()

        if event_type == "alert":
            if "specula test" in sig or "test" in sig:
                detections.append(
                    build_detection(
                        title="Signature réseau de test détectée",
                        description=(
                            f"Une signature de test Suricata a été observée sur le flux {pair}."
                        ),
                        severity="low",
                        category="security_event",
                        detection_type="network",
                        confidence=0.30,
                        rationale=(
                            "La signature déclenchée ressemble à une règle de test ou de validation."
                        ),
                        recommended_actions=[
                            "Vérifier s’il s’agit d’un trafic de validation interne",
                            "Écarter le bruit si ce test est volontaire",
                            "Conserver l’événement pour contrôle du pipeline",
                        ],
                        extra_tags=["test_signature"],
                    )
                )

            elif any(token in sig for token in ["scan", "nmap", "recon", "enumeration"]):
                detections.append(
                    build_detection(
                        title="Reconnaissance réseau détectée",
                        description=(
                            f"Une activité de scan ou de reconnaissance réseau a été détectée "
                            f"sur le flux {pair}."
                        ),
                        severity=normalized_severity,
                        category="network_reconnaissance",
                        detection_type="network",
                        confidence=0.60,
                        rationale=(
                            "La signature Suricata évoque une activité de scan, d’énumération ou de reconnaissance."
                        ),
                        recommended_actions=[
                            "Vérifier si l’adresse source est connue ou autorisée",
                            "Contrôler si la cible est exposée publiquement",
                            "Rechercher d’autres tentatives sur la même période",
                        ],
                        extra_tags=["scan"],
                    )
                )

            elif any(
                token in sig
                for token in ["brute force", "bruteforce", "password spray", "login attempt"]
            ):
                detections.append(
                    build_detection(
                        title="Tentative d’authentification réseau suspecte",
                        description=(
                            f"Une activité de type brute force ou tentative répétée d’authentification "
                            f"a été détectée sur le flux {pair}."
                        ),
                        severity="medium" if normalized_severity in {"low", "info"} else normalized_severity,
                        category="identity_attack",
                        detection_type="network",
                        confidence=0.75,
                        rationale=(
                            "La signature Suricata suggère des tentatives répétées ou agressives d’authentification."
                        ),
                        recommended_actions=[
                            "Vérifier le service ciblé et les logs d’authentification associés",
                            "Contrôler si la source a touché plusieurs cibles",
                            "Mettre en corrélation avec Wazuh ou les journaux applicatifs",
                        ],
                        extra_tags=["bruteforce"],
                    )
                )

            elif any(token in sig for token in ["malware", "trojan", "worm", "ransom", "backdoor"]):
                detections.append(
                    build_detection(
                        title="Indicateur réseau de malware détecté",
                        description=(
                            f"Un indicateur réseau lié à un malware ou comportement proche "
                            f"a été détecté sur le flux {pair}."
                        ),
                        severity="high" if normalized_severity in {"medium", "low", "info"} else normalized_severity,
                        category="malware",
                        detection_type="network",
                        confidence=0.85,
                        rationale=(
                            "La signature Suricata mentionne un comportement ou artefact associé à une activité malveillante."
                        ),
                        recommended_actions=[
                            "Identifier l’hôte concerné et isoler si nécessaire",
                            "Corréler avec les logs système et EDR si disponibles",
                            "Contrôler les flux voisins et la persistance éventuelle",
                        ],
                        extra_tags=["malware_candidate"],
                    )
                )

            elif any(token in sig for token in ["command and control", "c2", "beacon", "callback"]):
                detections.append(
                    build_detection(
                        title="Suspicion de canal de commande et contrôle",
                        description=(
                            f"Une activité réseau pouvant correspondre à du command-and-control "
                            f"a été détectée sur le flux {pair}."
                        ),
                        severity="high" if normalized_severity in {"medium", "low", "info"} else normalized_severity,
                        category="malware",
                        detection_type="network",
                        confidence=0.88,
                        rationale=(
                            "La signature évoque une communication réseau typique de beaconing ou de commande distante."
                        ),
                        recommended_actions=[
                            "Vérifier la destination et sa réputation",
                            "Chercher des connexions périodiques similaires",
                            "Corréler avec les événements système et proxy",
                        ],
                        extra_tags=["c2_candidate"],
                    )
                )

            elif any(token in sig for token in ["exploit", "shellcode", "overflow", "injection", "traversal"]):
                detections.append(
                    build_detection(
                        title="Tentative d’exploitation réseau détectée",
                        description=(
                            f"Une tentative d’exploitation ou un motif réseau offensif "
                            f"a été détecté sur le flux {pair}."
                        ),
                        severity="high" if normalized_severity in {"medium", "low", "info"} else normalized_severity,
                        category="host_compromise",
                        detection_type="network",
                        confidence=0.82,
                        rationale=(
                            "La signature Suricata mentionne un motif compatible avec une tentative d’exploitation."
                        ),
                        recommended_actions=[
                            "Vérifier le service ciblé et sa version",
                            "Contrôler si d’autres tentatives visent la même cible",
                            "Chercher des signes de compromission côté hôte",
                        ],
                        extra_tags=["exploitation_attempt"],
                    )
                )

            elif app_proto == "http" or any(
                token in sig for token in ["http", "user-agent", "web", "uri", "header"]
            ):
                detections.append(
                    build_detection(
                        title="Trafic HTTP suspect détecté",
                        description=(
                            f"Une alerte HTTP Suricata a été détectée sur le flux {pair}"
                            f"{f' vers {hostname}' if hostname else ''}"
                            f"{f' ({url})' if url else ''}."
                        ),
                        severity=normalized_severity,
                        category="suspicious_http",
                        detection_type="network",
                        confidence=0.65,
                        rationale=(
                            "Une signature réseau HTTP a été déclenchée sur un flux applicatif web."
                        ),
                        recommended_actions=[
                            "Vérifier l’URL et l’hôte ciblés",
                            "Corréler avec les journaux reverse proxy ou applicatifs",
                            "Contrôler si la requête est légitime ou malveillante",
                        ],
                        extra_tags=["http"],
                    )
                )

            elif app_proto == "dns" or "dns" in sig:
                detections.append(
                    build_detection(
                        title="Anomalie DNS détectée",
                        description=(
                            f"Une activité DNS suspecte a été détectée sur le flux {pair}. "
                            f"Domaine observé : {rrname or 'unknown'}."
                        ),
                        severity=normalized_severity,
                        category="dns_anomaly",
                        detection_type="network",
                        confidence=0.60,
                        rationale=(
                            "La détection Suricata concerne un échange DNS potentiellement anormal."
                        ),
                        recommended_actions=[
                            "Vérifier le domaine demandé",
                            "Contrôler la réputation et la légitimité de la requête",
                            "Corréler avec d’autres signaux réseau sur la même source",
                        ],
                        extra_tags=["dns"],
                    )
                )

            elif app_proto == "tls" or any(
                token in sig for token in ["tls", "ssl", "certificate", "sni"]
            ):
                detections.append(
                    build_detection(
                        title="Anomalie TLS détectée",
                        description=(
                            f"Une activité TLS suspecte a été détectée sur le flux {pair}. "
                            f"SNI observé : {sni or 'unknown'}."
                        ),
                        severity=normalized_severity,
                        category="tls_anomaly",
                        detection_type="network",
                        confidence=0.60,
                        rationale=(
                            "La détection Suricata concerne un échange TLS présentant un indicateur suspect."
                        ),
                        recommended_actions=[
                            "Vérifier le SNI observé",
                            "Contrôler si la destination est attendue",
                            "Corréler avec les logs proxy, DNS et firewall",
                        ],
                        extra_tags=["tls"],
                    )
                )

            elif "policy" in sig or "protocol-command-decode" in sig:
                detections.append(
                    build_detection(
                        title="Écart de politique réseau détecté",
                        description=(
                            f"Une alerte réseau de politique ou de conformité protocolaire "
                            f"a été détectée sur le flux {pair}."
                        ),
                        severity="low" if normalized_severity == "info" else normalized_severity,
                        category="security_event",
                        detection_type="network",
                        confidence=0.45,
                        rationale=(
                            "La signature semble relever d’un écart de politique ou d’un contrôle protocolaire."
                        ),
                        recommended_actions=[
                            "Vérifier si le trafic est attendu dans l’environnement",
                            "Qualifier le niveau réel de sensibilité",
                            "Réduire le bruit si cette règle remonte trop souvent",
                        ],
                        extra_tags=["policy_event"],
                    )
                )

            else:
                detections.append(
                    build_detection(
                        title=signature or "Alerte réseau Suricata",
                        description=(
                            f"Une alerte réseau Suricata a été détectée sur le flux {pair}."
                        ),
                        severity=normalized_severity,
                        category="network_alert",
                        detection_type="network",
                        confidence=0.55,
                        rationale=(
                            "La signature Suricata a déclenché une alerte réseau générique nécessitant qualification."
                        ),
                        recommended_actions=[
                            "Analyser la signature Suricata déclenchée",
                            "Vérifier le contexte réseau de la source et de la destination",
                            "Corréler avec d’autres événements proches temporellement",
                        ],
                    )
                )

        elif event_type == "dns":
            detections.append(
                build_detection(
                    title="Événement DNS à surveiller",
                    description=(
                        f"Un événement DNS a été observé sur le flux {pair}. "
                        f"Domaine : {rrname or 'unknown'}."
                    ),
                    severity="low",
                    category="dns_anomaly",
                    detection_type="network",
                    confidence=0.45,
                    rationale="Événement DNS remonté pour visibilité et corrélation réseau.",
                    recommended_actions=[
                        "Contrôler si le domaine est attendu",
                        "Corréler avec les autres événements réseau de la même source",
                    ],
                    extra_tags=["dns_event"],
                )
            )

        elif event_type == "http":
            detections.append(
                build_detection(
                    title="Événement HTTP à surveiller",
                    description=(
                        f"Un événement HTTP a été observé sur le flux {pair}"
                        f"{f' vers {hostname}' if hostname else ''}"
                        f"{f' ({url})' if url else ''}."
                    ),
                    severity="low",
                    category="http_event",
                    detection_type="network",
                    confidence=0.45,
                    rationale="Événement HTTP remonté pour visibilité et corrélation réseau.",
                    recommended_actions=[
                        "Vérifier l’URL et l’hôte demandés",
                        "Corréler avec les alertes réseau voisines",
                    ],
                    extra_tags=["http_event"],
                )
            )

        elif event_type == "tls":
            detections.append(
                build_detection(
                    title="Événement TLS à surveiller",
                    description=(
                        f"Un événement TLS a été observé sur le flux {pair}. "
                        f"SNI : {sni or 'unknown'}."
                    ),
                    severity="low",
                    category="tls_event",
                    detection_type="network",
                    confidence=0.45,
                    rationale="Événement TLS remonté pour visibilité et corrélation réseau.",
                    recommended_actions=[
                        "Vérifier le SNI et la destination",
                        "Corréler avec les événements DNS ou alertes voisines",
                    ],
                    extra_tags=["tls_event"],
                )
            )

        elif event_type == "anomaly":
            detections.append(
                build_detection(
                    title="Anomalie réseau détectée",
                    description=(
                        f"Une anomalie réseau a été observée sur le flux {pair}. "
                        f"Type : {anomaly_type or 'unknown'}, événement : {anomaly_event or 'unknown'}."
                    ),
                    severity="medium",
                    category="anomaly_event",
                    detection_type="network",
                    confidence=0.55,
                    rationale="Suricata a remonté une anomalie protocolaire ou réseau nécessitant revue.",
                    recommended_actions=[
                        "Vérifier la nature de l’anomalie et sa répétition",
                        "Contrôler si le flux est légitime",
                        "Corréler avec d’autres alertes sur la même cible",
                    ],
                    extra_tags=["anomaly"],
                )
            )

        elif event_type == "flow":
            has_payload = any(
                value not in (None, 0, "0")
                for value in [bytes_toserver, bytes_toclient, pkts_toserver, pkts_toclient]
            )

            if has_payload:
                detections.append(
                    build_detection(
                        title="Flux réseau observé",
                        description=(
                            f"Un flux réseau a été observé entre {format_endpoint(src_ip, src_port)} "
                            f"et {format_endpoint(dest_ip, dest_port)}."
                        ),
                        severity="info",
                        category="network_flow",
                        detection_type="network",
                        confidence=0.25,
                        rationale="Événement de flux remonté principalement pour visibilité et corrélation.",
                        recommended_actions=[
                            "Utiliser ce signal pour la corrélation avec d’autres alertes",
                        ],
                        extra_tags=["flow_event"],
                    )
                )

        return detections