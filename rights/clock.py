"""可替换的时钟。

业务时点若出现在消息内容中，以消息自报的时点为准；没有自报时点时用注入的
时钟。这样演练可以精确复现，生产可以替换为系统时间。
"""

from __future__ import annotations

from datetime import datetime, timezone


class Clock:
    def now(self) -> datetime:
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    """演练时钟：同一实例始终返回同一时点，保证回放一致。"""

    def __init__(self, start: str | datetime):
        if isinstance(start, str):
            start = datetime.fromisoformat(start)
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        self._value = start

    def now(self) -> datetime:
        return self._value
