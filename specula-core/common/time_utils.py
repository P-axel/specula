from datetime import datetime, timezone


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    raw = value.strip()

    if raw.endswith("Z"):
        raw = raw[:-1] + "+0000"

    if len(raw) >= 6 and raw[-3] == ":" and raw[-6] in {"+", "-"}:
        raw = raw[:-3] + raw[-2:]

    candidates = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ]

    for fmt in candidates:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def relative_time(value: str | None) -> str | None:
    dt = parse_datetime(value)
    if not dt:
        return None

    now = datetime.now(timezone.utc)
    delta = now - dt
    seconds = int(delta.total_seconds())

    if seconds < 60:
        return f"{seconds}s ago"

    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"

    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"

    days = hours // 24
    return f"{days}d ago"