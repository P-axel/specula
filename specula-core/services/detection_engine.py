from typing import Any, Dict, List

from services.risk_scoring import RiskScoringService


class DetectionEngine:
    def __init__(self) -> None:
        self.risk_scoring = RiskScoringService()

    def from_wazuh_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        detections: List[Dict[str, Any]] = []

        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        data = alert.get("data") or {}
        raw = alert.get("raw") or {}

        rule_id = str(rule.get("id") or "")
        rule_level = int(rule.get("level") or 0)
        rule_description = str(rule.get("description") or "").lower()
        rule_groups = [str(g).lower() for g in (rule.get("groups") or [])]

        agent_id = agent.get("id")
        agent_name = agent.get("name") or "unknown"
        agent_ip = agent.get("ip")
        timestamp = alert.get("timestamp") or alert.get("@timestamp")

        full_log = str(raw.get("full_log") or "").lower()
        previous_output = str(raw.get("previous_output") or "").lower()
        location = str(raw.get("location") or "").lower()

        src_user = str(data.get("srcuser") or "").strip()
        dst_user = str(data.get("dstuser") or "").strip()
        command = str(data.get("command") or "").strip()
        file_path = str(data.get("file") or "").strip().lower()
        title_value = str(data.get("title") or "").strip().lower()

        def build_detection(
            title: str,
            description: str,
            severity: str,
            category: str,
            framework: str,
            control_ref: str,
            detection_type: str = "security_event",
            confidence: float = 0.8,
            asset_criticality: str = "medium",
            rationale: str = "",
            recommended_actions: List[str] | None = None,
        ) -> Dict[str, Any]:
            detection = {
                "id": alert.get("id"),
                "title": title,
                "name": title,
                "description": description,
                "severity": severity,
                "confidence": confidence,
                "source": "wazuh",
                "source_rule_id": rule_id,
                "asset": agent_name,
                "asset_id": agent_id,
                "asset_name": agent_name,
                "hostname": agent_name,
                "asset_criticality": asset_criticality,
                "timestamp": timestamp,
                "created_at": timestamp,
                "category": category,
                "type": detection_type,
                "framework": framework,
                "control_ref": control_ref,
                "status": "open",
                "ip_address": agent_ip,
                "source_ip": alert.get("srcip"),
                "username": src_user or dst_user or None,
                "tags": rule_groups,
                "recommended_actions": recommended_actions or [],
                "metadata": {
                    "rule_description": rule.get("description"),
                    "rule_level": rule_level,
                    "rule_groups": rule.get("groups") or [],
                    "rationale": rationale,
                    "raw_data": data,
                    "location": raw.get("location"),
                },
                "raw": alert,
            }

            scored_detection = self.risk_scoring.score_detection(detection)

            # Compatibilité temporaire si le reste du pipeline attend "priority"
            if "risk_level" in scored_detection and "priority" not in scored_detection:
                scored_detection["priority"] = scored_detection["risk_level"]

            return scored_detection

        known_sensitive_but_noisy_files = {
            "/bin/passwd",
            "/usr/bin/passwd",
            "/bin/chfn",
            "/usr/bin/chfn",
            "/bin/chsh",
            "/usr/bin/chsh",
        }

        likely_legit_promisc_indicators = (
            "kdeconnect",
            "docker",
            "networkmanager",
            "libvirt",
            "vmware",
            "virtualbox",
            "podman",
            "bridge",
            "br-",
            "veth",
        )

        likely_admin_commands = (
            "systemctl ",
            "service ",
            "apt ",
            "apt-get ",
            "dnf ",
            "yum ",
            "docker ",
            "podman ",
            "journalctl ",
            "cat ",
            "ls ",
            "cp ",
            "mv ",
            "mkdir ",
            "chmod ",
            "chown ",
        )

        benign_exposed_ports = {
            "80",
            "443",
            "1514",
            "1515",
            "5173",
            "5432",
            "55000",
            "8443",
            "9200",
            "3306",
        }

        # 1) Rootcheck / possible trojan
        if (
            "rootcheck" in rule_groups
            or "trojaned version of file detected" in title_value
            or "host-based anomaly detection event" in rule_description
        ):
            if (
                "trojaned version of file detected" in title_value
                and file_path in known_sensitive_but_noisy_files
            ):
                detections.append(
                    build_detection(
                        title="Anomalie rootcheck à confirmer",
                        description=(
                            f"Rootcheck a signalé une possible altération sur {agent_name} "
                            f"({file_path}). Ce type de fichier est connu pour générer des "
                            f"alertes bruitées : contrôle manuel recommandé avant de conclure "
                            f"à une compromission."
                        ),
                        severity="medium",
                        category="host_anomaly",
                        framework="ISO 27001",
                        control_ref="A.8.16 Monitoring activities",
                        detection_type="investigation",
                        confidence=0.45,
                        rationale=(
                            "Alerte rootcheck sur fichier système sensible mais connu pour "
                            "générer des faux positifs fréquents."
                        ),
                        recommended_actions=[
                            "Comparer le hash du fichier avec la version du paquet installé",
                            "Vérifier l’intégrité via le gestionnaire de paquets",
                            "Contrôler les dates de modification et permissions",
                        ],
                    )
                )
            else:
                severity = "critical" if rule_level >= 9 else "high"
                confidence = 0.9 if "trojaned version of file detected" in title_value else 0.75

                detections.append(
                    build_detection(
                        title="Suspicion de compromission système",
                        description=(
                            f"Une anomalie rootcheck signale un fichier potentiellement "
                            f"trojanisé sur {agent_name} ({file_path or 'unknown file'})."
                        ),
                        severity=severity,
                        category="host_compromise",
                        framework="ISO 27001",
                        control_ref="A.8.7 Protection against malware",
                        detection_type="threat",
                        confidence=confidence,
                        rationale=(
                            "Signal rootcheck sur fichier ou comportement anormal hors des "
                            "cas bruités les plus classiques."
                        ),
                        recommended_actions=[
                            "Vérifier l’intégrité du fichier signalé",
                            "Comparer avec le paquet d’origine",
                            "Inspecter les processus et connexions réseau associés",
                        ],
                    )
                )

        # 2) Promiscuous mode / sniffing
        if (
            "promisc" in rule_groups
            or "promiscuous" in rule_description
            or rule_id == "5104"
        ):
            severity = "high"
            confidence = 0.85
            rationale = (
                "Le mode promiscuité peut être compatible avec de la capture réseau "
                "ou du sniffing."
            )

            legit_hit = any(indicator in full_log for indicator in likely_legit_promisc_indicators) or any(
                indicator in location for indicator in likely_legit_promisc_indicators
            )

            if legit_hit:
                severity = "medium"
                confidence = 0.55
                rationale = (
                    "Le mode promiscuité reste sensible mais le contexte évoque un usage "
                    "potentiellement légitime (Docker, bridge, KDE Connect, virtualisation)."
                )

            detections.append(
                build_detection(
                    title="Interface en mode promiscuité détectée",
                    description=(
                        f"Une interface réseau de {agent_name} est passée en mode "
                        f"promiscuité. Ce comportement peut correspondre à de la capture "
                        f"réseau, mais aussi à un usage légitime selon le contexte hôte."
                    ),
                    severity=severity,
                    category="network_sniffing",
                    framework="NIS2",
                    control_ref="Incident detection",
                    detection_type="network",
                    confidence=confidence,
                    rationale=rationale,
                    recommended_actions=[
                        "Vérifier si Docker, un bridge ou un outil réseau légitime est en cause",
                        "Contrôler les processus de capture réseau actifs",
                        "Confirmer l’état PROMISC avec 'ip link'",
                    ],
                )
            )

        # 3) Sudo / élévation de privilèges
        if (
            "sudo" in rule_groups
            or "successful sudo to root executed" in rule_description
            or rule_id == "5402"
        ):
            severity = "high"
            confidence = 0.85
            rationale = "Exécution d’une commande privilégiée via sudo."

            normalized_command = command.lower()

            if src_user in {"root", "p-axel"}:
                severity = "medium"
                confidence = 0.65
                rationale = (
                    "Élévation de privilèges réalisée par un utilisateur attendu dans un "
                    "contexte probablement administratif."
                )

            if normalized_command and any(token in normalized_command for token in likely_admin_commands):
                severity = "medium"
                confidence = min(confidence, 0.6)
                rationale = (
                    "Commande sudo cohérente avec une activité d’administration système."
                )

            if not command:
                confidence = min(confidence, 0.55)

            detections.append(
                build_detection(
                    title="Élévation de privilèges via sudo",
                    description=(
                        f"L’utilisateur {src_user or 'unknown'} a exécuté une commande "
                        f"privilégiée vers {dst_user or 'root'} sur {agent_name}: "
                        f"{command or 'unknown command'}"
                    ),
                    severity=severity,
                    category="privilege_abuse",
                    framework="NIS2",
                    control_ref="Detection of security incidents",
                    detection_type="privilege",
                    confidence=confidence,
                    rationale=rationale,
                    recommended_actions=[
                        "Vérifier si l’utilisateur est légitime sur cet hôte",
                        "Contrôler la commande exécutée et son objectif",
                        "Corréler avec d’autres signaux sur la même fenêtre temporelle",
                    ],
                )
            )

        # 4) Changement de ports d’écoute
        if rule_id == "533" or "listened ports status" in rule_description:
            severity = "medium"
            confidence = 0.7
            rationale = "Modification des services exposés détectée par netstat."

            combined_ports_text = f"{full_log}\n{previous_output}"

            benign_port_hits = sum(
                1 for port in benign_exposed_ports
                if f":{port}" in combined_ports_text
            )

            if benign_port_hits >= 2:
                severity = "low"
                confidence = 0.45
                rationale = (
                    "Le changement concerne vraisemblablement des ports attendus dans "
                    "l’environnement local ou de développement."
                )

            detections.append(
                build_detection(
                    title="Changement des services exposés",
                    description=(
                        f"Un changement des ports en écoute a été détecté sur {agent_name}. "
                        f"Ce signal peut refléter un déploiement, un redémarrage de service "
                        f"ou une nouvelle exposition réseau."
                    ),
                    severity=severity,
                    category="exposure_change",
                    framework="ISO 27001",
                    control_ref="A.8.16 Monitoring activities",
                    detection_type="configuration",
                    confidence=confidence,
                    rationale=rationale,
                    recommended_actions=[
                        "Vérifier les nouveaux ports ouverts",
                        "Confirmer si un service a été déployé ou redémarré",
                        "Contrôler si l’exposition réseau est attendue",
                    ],
                )
            )

        # 5) Service systemd en échec
        if (
            "systemd" in rule_groups
            or "service exited due to a failure" in rule_description
            or rule_id == "40704"
        ):
            severity = "medium"
            confidence = 0.7
            rationale = "Un service systemd a quitté avec une erreur."

            if "pulseaudio" in full_log or "autostart" in full_log:
                severity = "low"
                confidence = 0.45
                rationale = (
                    "Le service en échec semble lié à une composante utilisateur ou poste de "
                    "travail, avec impact sécurité probablement limité."
                )

            detections.append(
                build_detection(
                    title="Service système en échec",
                    description=(
                        f"Un service systemd est tombé en erreur sur {agent_name}. "
                        f"L’impact sécurité dépend du service concerné."
                    ),
                    severity=severity,
                    category="service_failure",
                    framework="ISO 27001",
                    control_ref="A.8.16 Monitoring activities",
                    detection_type="availability",
                    confidence=confidence,
                    rationale=rationale,
                    recommended_actions=[
                        "Identifier le service concerné",
                        "Vérifier si l’échec impacte la sécurité ou la disponibilité",
                        "Contrôler les journaux systemd associés",
                    ],
                )
            )

        # 6) Auth success sensible
        if "authentication_success" in rule_groups and rule_level >= 3:
            severity = "medium"
            confidence = 0.65
            rationale = "Authentification réussie sur compte sensible ou élévation de session."

            if dst_user in {"root", "administrator"}:
                severity = "medium"
                confidence = 0.75

            if src_user and dst_user and src_user == dst_user:
                severity = "low"
                confidence = 0.45
                rationale = (
                    "Ouverture de session cohérente avec une activité utilisateur locale "
                    "sans indice direct d’abus."
                )

            if src_user in {"p-axel", "root"} and dst_user in {"p-axel", "root"}:
                severity = "low"
                confidence = 0.5
                rationale = (
                    "Authentification sensible mais probablement légitime au vu des comptes "
                    "impliqués sur cette machine."
                )

            detections.append(
                build_detection(
                    title="Authentification réussie sensible",
                    description=(
                        f"Ouverture de session sensible détectée sur {agent_name} "
                        f"({src_user or 'unknown'} -> {dst_user or 'unknown'})."
                    ),
                    severity=severity,
                    category="identity_activity",
                    framework="NIS2",
                    control_ref="Monitoring and event handling",
                    detection_type="identity",
                    confidence=confidence,
                    rationale=rationale,
                    recommended_actions=[
                        "Confirmer que l’utilisateur est attendu",
                        "Vérifier l’heure et le contexte de la session",
                        "Corréler avec sudo, rootcheck ou autres anomalies sur l’hôte",
                    ],
                )
            )

        # 7) Fallback plus tolérant mais prudent
        if not detections and rule_level >= 7:
            severity = "high" if rule_level >= 10 else "medium"
            confidence = 0.6 if rule_level >= 10 else 0.5

            detections.append(
                build_detection(
                    title="Événement de sécurité Wazuh",
                    description=(
                        f"Alerte Wazuh de niveau {rule_level} détectée sur "
                        f"{agent_name}: {rule.get('description')}"
                    ),
                    severity=severity,
                    category="security_event",
                    framework="NIS2",
                    control_ref="Incident detection",
                    detection_type="security_event",
                    confidence=confidence,
                    rationale=(
                        "Aucun scénario métier spécifique n’a correspondu, mais le niveau "
                        "de l’alerte justifie une visibilité SOC."
                    ),
                    recommended_actions=[
                        "Inspecter l’alerte brute Wazuh",
                        "Qualifier le contexte de l’hôte",
                        "Créer une règle métier dédiée si ce cas revient souvent",
                    ],
                )
            )

        return detections