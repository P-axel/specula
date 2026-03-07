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