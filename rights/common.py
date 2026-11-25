"""服务层共用的小工具。"""

from __future__ import annotations

import re
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from .entities import Delivery
from .errors import ValidationError

IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,96}")


def iso(value) -> str | None:
    return None if value is None else value.isoformat()


def sanitize_identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-")[:96]
    if not cleaned:
        raise ValidationError("编号清洗后为空")
    return cleaned


def to_datetime(value, default=None) -> datetime | None:
    if value in (None, ""):
        return default
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime.combine(value, time(), tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    result = datetime.fromisoformat(text)
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def at_minute(day: date | None, minute: Any, fallback: datetime) -> datetime:
    """把消息里的相对分钟落到活动日；没有活动日则退回消息本身时点。"""
    if day is None or minute in (None, ""):
        return fallback
    try:
        offset = int(minute)
    except (TypeError, ValueError) as error:
        raise ValidationError(f"业务时点无效：{minute}") from error
    return datetime.combine(day, time(), tzinfo=timezone.utc) + timedelta(minutes=offset)


def message_time(payload: dict, event_minute: Any, day: date | None, fallback: datetime):
    """业务时点优先取消息自报的 published_at / at。"""
    if payload.get("published_at") is not None:
        return at_minute(day, payload["published_at"], fallback)
    if payload.get("at") is not None:
        parsed = to_datetime(payload["at"], None)
        if parsed is not None:
            return parsed
    if payload.get("minute") is not None:
        return at_minute(day, payload["minute"], fallback)
    return at_minute(day, event_minute, fallback)


def delivery_chain(deliveries: dict[str, Delivery], delivery: Delivery) -> list[str]:
    """从根交付到该交付的编号链，用于追到实际转载端。"""
    chain: list[str] = []
    seen = set()
    current: Delivery | None = delivery
    while current is not None and current.id not in seen:
        seen.add(current.id)
        chain.append(current.id)
        current = deliveries.get(current.parent_delivery) if current.parent_delivery else None
    return list(reversed(chain))


def descendants(deliveries: dict[str, Delivery], delivery_id: str) -> list[Delivery]:
    found = []
    frontier = [delivery_id]
    seen = {delivery_id}
    while frontier:
        parent = frontier.pop()
        for candidate in deliveries.values():
            if candidate.parent_delivery == parent and candidate.id not in seen:
                seen.add(candidate.id)
                found.append(candidate)
                frontier.append(candidate.id)
    return found
