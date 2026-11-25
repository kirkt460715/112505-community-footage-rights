"""演练台账的便捷载入。"""

from __future__ import annotations

import json
from pathlib import Path

from .clock import FixedClock
from .registers import RegisterBook
from .service import RightsService
from .transport import InMemoryReceiptTransport

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load_events(folder=FIXTURES):
    return [
        json.loads(line)
        for line in (Path(folder) / "events.ndjson").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_receipts(folder=FIXTURES):
    return json.loads((Path(folder) / "receipts.json").read_text(encoding="utf-8"))


def build_service(folder=FIXTURES, *, clock=None, transport=None):
    """按演练台账构造服务，默认接到消息里的活动日零点。"""
    folder = Path(folder)
    if clock is None:
        book = RegisterBook.from_file(folder / "registers.json")
        start = f"{book.activity_day.isoformat()}T00:00:00" if book.activity_day else "2000-01-01T00:00:00"
        clock = FixedClock(start)
        service = RightsService(book, clock=clock, transport=transport)
    else:
        service = RightsService.from_fixtures(folder, clock=clock, transport=transport)
    if transport is None:
        service.transport = InMemoryReceiptTransport(load_receipts(folder))
    return service


def replay_fixture(folder=FIXTURES):
    """把演练消息按送达顺序灌入并返回服务实例。"""
    service = build_service(folder)
    service.ingest_events(load_events(folder))
    return service


__all__ = ["Actor", "FIXTURES", "build_service", "load_events", "load_receipts", "replay_fixture"]
