from connectors.wazuh.client import WazuhClient
from connectors.wazuh.alerts import WazuhAlertsConnector
from normalization.wazuh_mapper import WazuhMapper


def main() -> None:
    client = WazuhClient()
    connector = WazuhAlertsConnector(client)

    alerts = connector.list_alerts(limit=5)

    print(f"{len(alerts)} alertes récupérées\n")

    for alert in alerts:
        normalized = WazuhMapper.to_dict(alert)
        print(normalized)
        print("-" * 80)


if __name__ == "__main__":
    main()