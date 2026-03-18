from typing import Any, Dict, Optional

from detection.wazuh_rule_mapping import WAZUH_RULE_MAPPINGS


def find_rule_mapping(rule_id: str | None, category_hint: str | None = None) -> Optional[Dict[str, Any]]:
    normalized_rule_id = str(rule_id).strip() if rule_id is not None else None
    normalized_category_hint = str(category_hint).strip().upper() if category_hint else None

    for mapping in WAZUH_RULE_MAPPINGS:
        rule_ids = mapping.get("rule_ids", set())

        if normalized_rule_id and normalized_rule_id in rule_ids:
            return mapping

        if normalized_category_hint and normalized_category_hint in rule_ids:
            return mapping

    return None