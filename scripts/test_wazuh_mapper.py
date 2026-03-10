from connectors.wazuh.wazuh_mapper import WazuhMapper


def main() -> None:
    sample_alert = {
        "id": "abc123",
        "timestamp": "2026-03-09T10:15:00Z",
        "agent": {
            "id": "001",
            "name": "srv-ad-01"
        },
        "rule": {
            "level": 10,
            "description": "Multiple authentication failures detected",
            "groups": ["authentication_failed", "windows"]
        },
        "full_log": "Failed login attempts detected on srv-ad-01"
    }

    event = WazuhMapper.to_normalized_event(sample_alert)

    print("Objet :")
    print(event)
    print()

    print("Dict :")
    print(event.to_dict())
    print()

    print("Résumé :")
    print(
        f"source={event.source}, severity={event.severity}, "
        f"asset={event.asset_name}, title={event.title}"
    )


if __name__ == "__main__":
    main()