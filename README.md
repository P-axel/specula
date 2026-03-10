# Specula

Specula is a security visibility platform designed to supervise infrastructure,
collect telemetry from multiple security tools and provide a unified SOC view.

The project is developed by RootSentinel.

Specula acts as an **intelligence layer** on top of trusted open-source
security components while keeping them unmodified.

---

# Goals

Specula aims to provide:

- unified visibility across infrastructure
- normalized security telemetry
- detection and alert generation
- automation capabilities for remediation
- a deployable master / client security platform

---

# Core Principles

Specula follows strict engineering principles:

- no fork of upstream tools
- modular architecture
- canonical security data model
- easy deployment
- extensible connectors
- product-grade interface

---

# Core Data Model

Specula is built around four canonical objects:

```
Asset  → infrastructure element
Event  → normalized telemetry
Alert  → interpreted security signal
Action → automated or recommended response
```

These objects allow Specula to integrate multiple telemetry sources while
keeping a consistent internal model.

---

# Architecture Overview

```
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
```

Specula integrates telemetry sources through connectors and converts them
into normalized objects used by the detection engine.

---

# Repository Structure

```
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
```

---

# Current Features

Specula currently provides:

- Wazuh integration
- asset discovery
- event normalization
- alert generation
- FastAPI backend
- React console
- modular architecture ready for additional telemetry sources

---

# Quick Start (Development)

## Start Wazuh

```
cd deploy/master/wazuh/single-node
docker compose up -d
```

Access Wazuh:

```
https://localhost:8443
```

---

## Start Specula API

```
source .venv/bin/activate

set -a
source .env.local
set +a

PYTHONPATH=specula-core uvicorn api.main:app --reload
```

API documentation:

```
http://127.0.0.1:8000/docs
```

---

## Start Specula Console

```
cd specula-console
npm run dev
```

Console:

```
http://localhost:5173
```

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

Instead it acts as an **intelligence layer** that:

- aggregates telemetry
- normalizes security signals
- correlates events
- generates alerts
- enables automated responses

---

# License

MIT License