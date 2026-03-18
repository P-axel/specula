from datetime import datetime, timezone
from common.time_utils import parse_datetime


def compute_health(status: str, last_seen: str | None) -> str:

    if status in ["disconnected", "inactive", "never_connected"]:
        return "critical"

    dt = parse_datetime(last_seen)

    if not dt:
        return "warning"

    now = datetime.now(timezone.utc)
    age = (now - dt).total_seconds()

    if age < 300:
        return "healthy"

    if age < 1800:
        return "warning"

    return "critical"