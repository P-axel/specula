# Specula
specula/
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── docs/
│   ├── architecture.md
│   ├── deployment.md
│   ├── roadmap.md
│   └── decisions/
│       ├── 0001-stack-choice.md
│       ├── 0002-master-client-model.md
│       └── 0003-no-fork-open-source.md
├── deploy/
│   ├── master/
│   │   ├── compose.yml
│   │   ├── .env.example
│   │   ├── install.sh
│   │   ├── upgrade.sh
│   │   └── healthcheck.sh
│   ├── client/
│   │   ├── compose.yml
│   │   ├── .env.example
│   │   ├── install.sh
│   │   ├── enroll.sh
│   │   └── healthcheck.sh
│   └── shared/
│       ├── scripts/
│       ├── templates/
│       └── certs/
├── specula-core/
│   ├── api/
│   ├── correlator/
│   ├── normalizer/
│   ├── notifier/
│   └── common/
├── specula-console/
│   ├── frontend/
│   └── assets/
├── integrations/
│   ├── wazuh/
│   ├── suricata/
│   ├── zeek/
│   ├── crowdsec/
│   ├── opensearch/
│   ├── prometheus/
│   └── grafana/
├── config/
│   ├── tenants/
│   ├── policies/
│   ├── rules/
│   └── mappings/
├── scripts/
│   ├── bootstrap-dev.sh
│   ├── lint.sh
│   └── test.sh
└── tests/
    ├── integration/
    └── fixtures/


    # Specula

Specula is a security supervision platform powered by RootSentinel.

## Goals
- Supervise Linux infrastructure
- Detect security threats
- Monitor network activity
- Correlate alerts from trusted open source components
- Provide a deployable master + client product

## Architecture
Specula is built as a product layer on top of open source security components kept unmodified:
- Wazuh
- Suricata
- Zeek
- CrowdSec
- OpenSearch
- Prometheus
- Grafana

## Principles
- No fork of upstream tools
- Easy deployment
- Multi-tenant ready
- Product-grade interface
- Master / client model

## Repository layout
...



                 +--------------------+
                 |  Specula Console   |
                 |  (UI / dashboards) |
                 +---------▲----------+
                           │ API
                 +---------▼----------+
                 |     Specula Core   |
                 |  Intelligence SOC  |
                 +----▲---------▲-----+
                      │         │
              Connectors   Modules
                      │         │
        +-------------▼---+ +---▼-------------+
        |   Wazuh / IDS   | | Extensions      |
        |   Suricata      | | PME / OT / etc  |
        +-----------------+ +-----------------+



        SPECULA/
├── README.md
├── LICENSE
├── .gitignore
├── .editorconfig
├── .env.example
│
├── config/
│   ├── environments/
│   │   ├── dev.env.example
│   │   ├── staging.env.example
│   │   └── prod.env.example
│   ├── modules/
│   │   ├── default.yml
│   │   ├── pme.yml
│   │   ├── industrie.yml
│   │   └── multisite.yml
│   └── policies/
│       ├── security.yml
│       ├── retention.yml
│       └── scoring.yml
│
├── deploy/
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   ├── .env.example
│   ├── reverse-proxy/
│   │   ├── nginx.conf
│   │   └── conf.d/
│   ├── scripts/
│   │   ├── install.sh
│   │   ├── update.sh
│   │   ├── backup.sh
│   │   ├── restore.sh
│   │   ├── healthcheck.sh
│   │   └── migrate.sh
│   ├── backups/
│   │   └── .gitkeep
│   └── volumes/
│       └── .gitkeep
│
├── docs/
│   ├── architecture/
│   │   ├── core.md
│   │   ├── modules.md
│   │   ├── deployment.md
│   │   └── data-model.md
│   ├── api/
│   │   └── openapi.md
│   ├── operations/
│   │   ├── install.md
│   │   ├── update.md
│   │   ├── backup.md
│   │   └── restore.md
│   └── security/
│       ├── hardening.md
│       ├── secrets.md
│       └── access-control.md
│
├── modules/
│   ├── README.md
│   ├── pme/
│   │   ├── module.yml
│   │   ├── rules/
│   │   ├── recommendations/
│   │   └── dashboards/
│   ├── industrie/
│   │   ├── module.yml
│   │   ├── rules/
│   │   ├── recommendations/
│   │   └── dashboards/
│   ├── multisite/
│   │   ├── module.yml
│   │   ├── rules/
│   │   ├── recommendations/
│   │   └── dashboards/
│   └── executive-reporting/
│       ├── module.yml
│       ├── templates/
│       └── dashboards/
│
├── scripts/
│   ├── bootstrap.sh
│   ├── dev.sh
│   └── lint.sh
│
├── specula-core/
│   ├── README.md
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── migrations/
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── router.py
│   │   │   ├── deps.py
│   │   │   ├── middleware/
│   │   │   │   ├── auth.py
│   │   │   │   ├── logging.py
│   │   │   │   └── security.py
│   │   │   └── routes/
│   │   │       ├── health.py
│   │   │       ├── auth.py
│   │   │       ├── assets.py
│   │   │       ├── events.py
│   │   │       ├── incidents.py
│   │   │       ├── vulnerabilities.py
│   │   │       ├── recommendations.py
│   │   │       └── modules.py
│   │   ├── auth/
│   │   │   ├── jwt.py
│   │   │   ├── rbac.py
│   │   │   ├── password.py
│   │   │   └── models.py
│   │   ├── config/
│   │   │   ├── settings.py
│   │   │   ├── logging.py
│   │   │   └── modules.py
│   │   ├── connectors/
│   │   │   ├── base.py
│   │   │   ├── wazuh/
│   │   │   │   ├── client.py
│   │   │   │   ├── alerts.py
│   │   │   │   ├── agents.py
│   │   │   │   └── vulnerabilities.py
│   │   │   └── suricata/
│   │   │       ├── client.py
│   │   │       ├── alerts.py
│   │   │       └── eve_parser.py
│   │   ├── normalization/
│   │   │   ├── base.py
│   │   │   ├── models.py
│   │   │   ├── wazuh_mapper.py
│   │   │   └── suricata_mapper.py
│   │   ├── correlation/
│   │   │   ├── engine.py
│   │   │   ├── base_rule.py
│   │   │   └── rules/
│   │   │       ├── brute_force.py
│   │   │       ├── scan_network.py
│   │   │       └── vulnerable_asset.py
│   │   ├── scoring/
│   │   │   ├── engine.py
│   │   │   ├── priority.py
│   │   │   └── impact.py
│   │   ├── storage/
│   │   │   ├── database.py
│   │   │   ├── session.py
│   │   │   ├── base.py
│   │   │   └── repositories/
│   │   │       ├── assets.py
│   │   │       ├── events.py
│   │   │       ├── incidents.py
│   │   │       └── vulnerabilities.py
│   │   ├── models/
│   │   │   ├── asset.py
│   │   │   ├── event.py
│   │   │   ├── incident.py
│   │   │   ├── vulnerability.py
│   │   │   ├── recommendation.py
│   │   │   └── module_config.py
│   │   ├── schemas/
│   │   │   ├── asset.py
│   │   │   ├── event.py
│   │   │   ├── incident.py
│   │   │   ├── vulnerability.py
│   │   │   ├── recommendation.py
│   │   │   └── auth.py
│   │   ├── services/
│   │   │   ├── asset_service.py
│   │   │   ├── ingestion_service.py
│   │   │   ├── incident_service.py
│   │   │   ├── vulnerability_service.py
│   │   │   ├── module_service.py
│   │   │   └── reporting_service.py
│   │   ├── plugins/
│   │   │   ├── loader.py
│   │   │   ├── registry.py
│   │   │   └── interfaces.py
│   │   ├── audit/
│   │   │   ├── logger.py
│   │   │   └── events.py
│   │   ├── observability/
│   │   │   ├── health.py
│   │   │   ├── metrics.py
│   │   │   └── tracing.py
│   │   ├── tasks/
│   │   │   ├── sync_wazuh.py
│   │   │   ├── sync_suricata.py
│   │   │   ├── cleanup.py
│   │   │   └── reports.py
│   │   └── utils/
│   │       ├── datetime.py
│   │       ├── ids.py
│   │       └── validators.py
│   └── tests/
│       ├── unit/
│       ├── integration/
│       └── fixtures/
│
├── specula-console/
│   ├── README.md
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.js
│   ├── public/
│   │   └── favicon.ico
│   └── frontend/
│       ├── index.html
│       └── src/
│           ├── main.jsx
│           ├── App.jsx
│           ├── app/
│           │   ├── router.jsx
│           │   ├── store.js
│           │   └── providers.jsx
│           ├── pages/
│           │   ├── DashboardPage.jsx
│           │   ├── AssetsPage.jsx
│           │   ├── IncidentsPage.jsx
│           │   ├── VulnerabilitiesPage.jsx
│           │   ├── RecommendationsPage.jsx
│           │   ├── ModulesPage.jsx
│           │   ├── LoginPage.jsx
│           │   └── SettingsPage.jsx
│           ├── components/
│           │   ├── layout/
│           │   ├── dashboard/
│           │   ├── assets/
│           │   ├── incidents/
│           │   ├── vulnerabilities/
│           │   ├── recommendations/
│           │   ├── modules/
│           │   └── common/
│           ├── services/
│           │   ├── api.js
│           │   ├── auth.js
│           │   ├── incidents.js
│           │   ├── assets.js
│           │   ├── vulnerabilities.js
│           │   └── modules.js
│           ├── hooks/
│           │   ├── useAuth.js
│           │   ├── useAssets.js
│           │   ├── useIncidents.js
│           │   └── useVulnerabilities.js
│           ├── styles/
│           │   ├── global.css
│           │   └── tokens.css
│           └── utils/
│               ├── formatters.js
│               └── constants.js
│
└── tests/
    ├── e2e/
    ├── security/
    └── performance/




    Lancement:


cd ~/dev/projets/projets-pro/specula/deploy/master/wazuh/single-node
docker compose up -d

https://localhost:8443