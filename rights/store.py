"""服务内部的可变状态。"""

from __future__ import annotations

from dataclasses import dataclass, field

from .entities import (
    Delivery,
    HandlingRequest,
    Revocation,
    Review,
    UnauthorizedCopy,
    Violation,
)
from .registers import RegisterBook


@dataclass
class Store:
    book: RegisterBook
    reviews: dict[str, Review] = field(default_factory=dict)
    review_order: list[str] = field(default_factory=list)
    deliveries: dict[str, Delivery] = field(default_factory=dict)
    delivery_order: list[str] = field(default_factory=list)
    revocations: dict[str, Revocation] = field(default_factory=dict)
    revocation_order: list[str] = field(default_factory=list)
    requests: dict[str, HandlingRequest] = field(default_factory=dict)
    request_order: list[str] = field(default_factory=list)
    violations: dict[str, Violation] = field(default_factory=dict)
    violation_order: list[str] = field(default_factory=list)
    unauthorized: dict[str, UnauthorizedCopy] = field(default_factory=dict)
    unauthorized_order: list[str] = field(default_factory=list)
    # 由台账或外部事实登记的直接许可，按人/渠道/版本/用途匹配。
    extra_direct: list = field(default_factory=list)
    # 事件处理幂等：已处理的事件指纹。
    seen_events: dict[str, dict] = field(default_factory=dict)
    sequence: int = 0

    def next_id(self, prefix: str) -> str:
        self.sequence += 1
        return f"{prefix}-{self.sequence:04d}"
