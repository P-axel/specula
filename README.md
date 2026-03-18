# Specula

![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-active-green)
![Backend](https://img.shields.io/badge/backend-FastAPI-blue)
![Frontend](https://img.shields.io/badge/frontend-React-blue)

Specula is a **security visibility platform** designed to supervise infrastructure,  
collect telemetry from multiple security tools, and provide a **unified SOC view**.

Developed and maintained by **RootSentinel**.

Specula acts as an **intelligence layer** on top of trusted open-source security components —  
without modifying or forking them.

---

# Why Specula?

Modern security stacks are **fragmented by design**.

Organizations rely on multiple tools (EDR, SIEM, IDS, logs),  
but lack a **unified, coherent intelligence layer** to correlate and act on signals.

Specula addresses this gap by:

- unifying telemetry into a **canonical data model**
- correlating signals across heterogeneous tools
- transforming raw events into **actionable security insights**

---

# Goals

Specula aims to provide:

- unified visibility across infrastructure
- normalized and structured security telemetry
- detection and alert generation
- automation capabilities for remediation
- a deployable **master / client security platform**

---

# Use Cases

Specula is designed for real-world security operations:

- SOC visibility across multiple tools
- centralized alert correlation
- infrastructure security monitoring
- automated incident response
- MSSP multi-client supervision

---

# Core Principles

Specula follows strict engineering principles:

- no fork of upstream tools
- modular and extensible architecture
- canonical security data model
- simple and reproducible deployment
- connector-based integrations
- product-grade interface and UX

---

# Connectors vs Modules

Specula distinguishes two key extension mechanisms:

- **Connectors** → ingest and normalize data from external tools (Wazuh, Suricata, etc.)
- **Modules** → extend internal capabilities (correlation, scoring, automation, detection)

This separation ensures scalability and clean architecture evolution.

---

# Core Data Model

Specula is built around four canonical objects:

Asset  → infrastructure element  
Event  → normalized telemetry  
Alert  → interpreted security signal  
Action → automated or recommended response  

This model enables consistent processing of heterogeneous data sources  
while maintaining a unified internal representation.

---

# Architecture Overview

                 +--------------------+
                 |  Specula Console   |
                 |  UI / dashboards   |
                 +---------▲----------+
                           │ API
                 +---------▼----------+
                 |     Specula Core   |
                 | Security Engine    |
                 +----▲---------▲-----+
                      │         │
                Connectors   Modules
                      │         │
        +-------------▼---+ +---▼-------------+
        |     Wazuh       | | Extensions      |
        |     Suricata    | | modules         |
        +-----------------+ +-----------------+

Specula integrates telemetry sources through connectors and converts them  
into normalized objects used by the detection and correlation engine.

---

# Repository Structure

SPECULA/
│
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
│
├── docs/
│   ├── architecture.md
│   ├── deployment.md
│   └── roadmap.md
│
├── deploy/
│   ├── master/
│   ├── client/
│   └── shared/
│
├── specula-core/
│   ├── api/
│   │   └── main.py
│   │
│   ├── common/
│   │   ├── asset.py
│   │   ├── event.py
│   │   ├── alert.py
│   │   └── action.py
│   │
│   ├── connectors/
│   │   └── wazuh/
│   │
│   ├── normalization/
│   │   ├── asset_normalizer.py
│   │   ├── event_normalizer.py
│   │   └── alert_normalizer.py
│   │
│   ├── services/
│   │   ├── assets_service.py
│   │   ├── events_service.py
│   │   └── alerts_service.py
│   │
│   ├── storage/
│   ├── config/
│   └── specula_logging/
│
├── specula-console/
│   ├── frontend/
│   └── assets/
│
├── integrations/
│   ├── wazuh/
│   ├── suricata/
│   ├── zeek/
│   ├── crowdsec/
│   └── observability/
│
├── scripts/
│   ├── bootstrap-dev.sh
│   ├── lint.sh
│   └── test.sh
│
└── tests/



# Current Features

Specula currently provides:

- Wazuh integration
- asset discovery
- event normalization
- alert generation
- FastAPI backend
- React-based console
- modular architecture ready for new telemetry sources

---

# Quick Start

Requirements:
- Docker
- Docker Compose

Then run:

git clone <repo>
cd specula
chmod +x start-specula.sh
./start-specula.sh

This will automatically:
- start Wazuh stack
- start Specula backend
- start Specula frontend
- register a default agent

Access:
- Specula Console: http://localhost:5173
- Specula API: http://127.0.0.1:8000/docs
- Wazuh Dashboard: https://localhost:8443

# Local Development (Optional)

If you prefer running locally without Docker:

./start

This script will:

- activate backend environment
- load environment variables
- start the API
- start the frontend

---

## Access

- Frontend: http://localhost:5173  
- API Docs: http://127.0.0.1:8000/docs  
- Wazuh: https://localhost:8443  

---

# Roadmap

Planned next steps:

- Suricata integration
- network telemetry ingestion
- detection rules engine
- automated remediation
- incident management
- multi-tenant support

---

# Philosophy

Specula does **not replace security tools**.

Instead, it acts as an **intelligence layer** that:

- aggregates telemetry
- normalizes security signals
- correlates events across sources
- generates actionable alerts
- enables automated responses

---

# Disclaimer

Specula is currently under active development.

It should not be used in production environments without proper validation  
and security review.

---

# License

MIT License
