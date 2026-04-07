"""
Mapping MITRE ATT&CK pour les alertes Specula.

Couvre les règles Suricata (classtype) et les règles Wazuh (rule groups/ids).
Format : technique_id, tactic, sous-technique optionnel, description.

Référence : https://attack.mitre.org/
"""
from __future__ import annotations

from typing import TypedDict


class MitreEntry(TypedDict):
    technique_id: str
    technique_name: str
    tactic: str
    sub_technique_id: str | None
    sub_technique_name: str | None


# ─── Mapping par classtype Suricata ────────────────────────────────────────────
SURICATA_CLASSTYPE_TO_MITRE: dict[str, MitreEntry] = {
    "attempted-recon": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "sub_technique_id": "T1595.001",
        "sub_technique_name": "Scanning IP Blocks",
    },
    "network-scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "attempted-dos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "denial-of-service": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "trojan-activity": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "command-and-control": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "attempted-admin": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "web-application-attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "sql-injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "protocol-command-decode": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "shellcode-detect": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "successful-recon-largescale": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "sub_technique_id": "T1595.001",
        "sub_technique_name": "Scanning IP Blocks",
    },
    "successful-recon-limited": {
        "technique_id": "T1590",
        "technique_name": "Gather Victim Network Information",
        "tactic": "Reconnaissance",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "misc-attack": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "policy-violation": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "sensitive-data": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "default-login-attempt": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "sub_technique_id": "T1078.001",
        "sub_technique_name": "Default Accounts",
    },
    "brute-force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "credential-theft": {
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "exploit-kit": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "malware-cnc": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "dns-query": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": "T1071.004",
        "sub_technique_name": "DNS",
    },
    "not-suspicious": None,
    "unknown": None,
}

# ─── Mapping par signature Suricata (mots-clés dans le titre) ─────────────────
SURICATA_SIGNATURE_KEYWORDS: list[tuple[str, MitreEntry]] = [
    ("brute force", {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_technique_id": "T1110.001",
        "sub_technique_name": "Password Guessing",
    }),
    ("ssh", {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "sub_technique_id": "T1021.004",
        "sub_technique_name": "SSH",
    }),
    ("sql injection", {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("path traversal", {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("dns tunnel", {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": "T1071.004",
        "sub_technique_name": "DNS",
    }),
    ("dns exfil", {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "sub_technique_id": "T1048.001",
        "sub_technique_name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
    }),
    ("dga", {
        "technique_id": "T1568",
        "technique_name": "Dynamic Resolution",
        "tactic": "Command and Control",
        "sub_technique_id": "T1568.002",
        "sub_technique_name": "Domain Generation Algorithms",
    }),
    ("c2", {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("metasploit", {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("backdoor", {
        "technique_id": "T1546",
        "technique_name": "Event Triggered Execution",
        "tactic": "Persistence",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("scan", {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("flood", {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "sub_technique_id": "T1498.001",
        "sub_technique_name": "Direct Network Flood",
    }),
    ("ftp", {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("telnet", {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("php", {
        "technique_id": "T1505",
        "technique_name": "Server Software Component",
        "tactic": "Persistence",
        "sub_technique_id": "T1505.003",
        "sub_technique_name": "Web Shell",
    }),
    ("upload", {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
    ("irc", {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique_id": None,
        "sub_technique_name": None,
    }),
]

# ─── Mapping pour les groupes de règles Wazuh ─────────────────────────────────
WAZUH_GROUP_TO_MITRE: dict[str, MitreEntry] = {
    "authentication_failed": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_technique_id": "T1110.001",
        "sub_technique_name": "Password Guessing",
    },
    "authentication_success": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "sshd": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "sub_technique_id": "T1021.004",
        "sub_technique_name": "SSH",
    },
    "sudo": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "sub_technique_id": "T1548.003",
        "sub_technique_name": "Sudo and Sudo Caching",
    },
    "rootcheck": {
        "technique_id": "T1014",
        "technique_name": "Rootkit",
        "tactic": "Defense Evasion",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "syscheck": {
        "technique_id": "T1565",
        "technique_name": "Data Manipulation",
        "tactic": "Impact",
        "sub_technique_id": "T1565.001",
        "sub_technique_name": "Stored Data Manipulation",
    },
    "virus": {
        "technique_id": "T1587",
        "technique_name": "Develop Capabilities",
        "tactic": "Resource Development",
        "sub_technique_id": "T1587.001",
        "sub_technique_name": "Malware",
    },
    "web": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "web-attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "pam": {
        "technique_id": "T1556",
        "technique_name": "Modify Authentication Process",
        "tactic": "Credential Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
    },
    "firewall": {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "sub_technique_id": "T1562.004",
        "sub_technique_name": "Disable or Modify System Firewall",
    },
    "windows": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "sub_technique_id": "T1059.003",
        "sub_technique_name": "Windows Command Shell",
    },
    "powershell": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "sub_technique_id": "T1059.001",
        "sub_technique_name": "PowerShell",
    },
}


def lookup_suricata(
    classtype: str | None,
    signature: str | None,
) -> MitreEntry | None:
    """
    Retourne l'entrée MITRE correspondant à une alerte Suricata.
    Priorité : classtype > mots-clés dans la signature.
    """
    if classtype:
        key = classtype.strip().lower()
        entry = SURICATA_CLASSTYPE_TO_MITRE.get(key)
        if entry is not None:
            return entry

    if signature:
        sig_lower = signature.strip().lower()
        for keyword, entry in SURICATA_SIGNATURE_KEYWORDS:
            if keyword in sig_lower:
                return entry

    return None


def lookup_wazuh(groups: list[str] | None) -> MitreEntry | None:
    """
    Retourne la première entrée MITRE correspondant aux groupes Wazuh.
    """
    if not groups:
        return None

    for group in groups:
        key = group.strip().lower()
        entry = WAZUH_GROUP_TO_MITRE.get(key)
        if entry:
            return entry

    return None


def format_techniques(entry: MitreEntry | None) -> list[str]:
    """Retourne la liste de technique IDs pour un incident."""
    if not entry:
        return []
    techniques = [entry["technique_id"]]
    if entry.get("sub_technique_id"):
        techniques.append(entry["sub_technique_id"])
    return techniques
