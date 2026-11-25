"""领域对象。

人物编号都是演练用编号；本模块不存储、也不接受任何身份证明材料。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from .model import DeliveryState, ReviewState


@dataclass(frozen=True)
class Span:
    clip: str
    start: int
    end: int

    def as_list(self):
        return [self.clip, self.start, self.end]

    def contains(self, start: int, end: int) -> bool:
        return self.start <= start and end <= self.end


@dataclass(frozen=True)
class Face:
    person: str
    start: int
    end: int


@dataclass
class Source:
    id: str
    length_ms: int
    faces: tuple[Face, ...] = ()

    def faces_in(self, start: int, end: int) -> list[Face]:
        """返回与 ``[start, end)`` 相交的可识别人员区间。"""
        return [f for f in self.faces if f.start < end and start < f.end]


@dataclass
class Authorization:
    id: str
    person: str
    uses: frozenset[str]
    valid_from: date | None = None
    until: date | None = None
    origin: str = "register"

    def within_window(self, at: datetime) -> bool:
        day = at.date()
        if self.valid_from and day < self.valid_from:
            return False
        if self.until and day > self.until:
            return False
        return True


@dataclass(frozen=True)
class DirectPermission:
    """授权人曾单独向某渠道、某版本给出的同用途许可。"""

    id: str
    person: str
    channel: str
    version: str
    use: str
    valid_from: date | None = None
    until: date | None = None

    def within_window(self, at: datetime) -> bool:
        day = at.date()
        if self.valid_from and day < self.valid_from:
            return False
        if self.until and day > self.until:
            return False
        return True


@dataclass(frozen=True)
class DeliveryScope:
    """县级账号给出的转载许可：限定来源、去向、成品、版本、用途与再转递。"""

    id: str
    source: str
    target: str
    edit: str
    use: str
    version: str | None = None
    can_forward: bool = False
    valid_from: date | None = None
    until: date | None = None

    def within_window(self, at: datetime) -> bool:
        day = at.date()
        if self.valid_from and day < self.valid_from:
            return False
        if self.until and day > self.until:
            return False
        return True

    def matches(self, *, source, target, edit, use, version, at) -> bool:
        if (self.source, self.target, self.edit, self.use) != (source, target, edit, use):
            return False
        if self.version is not None and version is not None and self.version != version:
            return False
        return self.within_window(at)


@dataclass
class EditVersion:
    id: str
    edit: str
    kind: str
    uses: frozenset[str]
    spans: tuple[Span, ...]
    created_by: str | None = None
    created_at: datetime | None = None
    derived_from: str | None = None
    verified_masks: tuple[tuple[str, str, int, int], ...] = ()

    def fingerprint(self) -> tuple:
        """版本内容指纹。审核只对相同指纹的版本有效。"""
        return (self.kind, tuple(s.as_list() for s in self.spans), tuple(sorted(self.uses)))


@dataclass
class Edit:
    id: str
    versions: dict[str, EditVersion] = field(default_factory=dict)
    current_version: str | None = None

    def version(self, version_id: str | None = None) -> EditVersion | None:
        return self.versions.get(version_id or self.current_version)

    @property
    def uses(self) -> frozenset[str]:
        version = self.version()
        return version.uses if version else frozenset()


@dataclass(frozen=True)
class Annotation:
    span_index: int
    persons: tuple[str, ...]
    recognized: bool
    note: str | None = None


@dataclass(frozen=True)
class Mask:
    person: str
    clip: str
    start: int
    end: int
    method: str
    span_index: int

    def as_dict(self):
        return {
            "person": self.person,
            "clip": self.clip,
            "start": self.start,
            "end": self.end,
            "method": self.method,
            "span_index": self.span_index,
            "reviewed_segment_only": True,
        }


@dataclass
class Review:
    id: str
    edit: str
    version: str
    kind: str
    state: ReviewState
    scope_indices: tuple[int, ...]
    submitted_by: str | None = None
    submitted_at: datetime | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    annotations: dict[int, Annotation] = field(default_factory=dict)
    masks: list[Mask] = field(default_factory=list)
    fingerprint: tuple = ()
    internal_only: bool = False
    trusted: bool = False
    seed: bool = False
    superseded_by: str | None = None
    note: str | None = None

    def active(self) -> bool:
        return self.superseded_by is None and self.state is ReviewState.APPROVED


@dataclass
class Delivery:
    id: str
    edit: str
    version: str
    channel: str
    use: str
    parent_delivery: str | None
    state: DeliveryState
    published_at: datetime
    received_at: datetime | None = None
    review_id: str | None = None
    authorized_scope: str | None = None
    source_event: int | None = None
    created_at: datetime | None = None
    created_by: str | None = None
    copies_withdrawn: bool = False
    still_displayed: tuple[str, ...] = ()
    cancelled: bool = False
    notes: list[str] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)

    def visible(self) -> bool:
        """是否仍有对外可见的副本。"""
        return self.state in {
            DeliveryState.PUBLISHED,
            DeliveryState.HELD,
            DeliveryState.STILL_DISPLAYED,
            DeliveryState.REPORTED,
        } and not self.cancelled


@dataclass
class Revocation:
    id: str
    authorization: str
    person: str
    use: str
    at: datetime
    by: str | None = None
    sequence: int = 0


@dataclass
class HandlingRequest:
    id: str
    channel: str
    delivery: str
    revocation: str
    operation: str
    reference: str
    status: str = "planned"
    receipt: dict[str, Any] | None = None
    created_at: datetime | None = None
    attempts: int = 0
    detail: str | None = None

    def as_dict(self):
        return {
            "id": self.id,
            "channel": self.channel,
            "delivery": self.delivery,
            "revocation": self.revocation,
            "operation": self.operation,
            "reference": self.reference,
            "status": self.status,
            "receipt": self.receipt,
            "attempts": self.attempts,
            "detail": self.detail,
        }


@dataclass
class Violation:
    id: str
    kind: str
    delivery: str | None
    destination: str | None
    detail: str
    at: datetime | None = None
    status: str = "open"
    related: str | None = None

    def as_dict(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "delivery": self.delivery,
            "destination": self.destination,
            "detail": self.detail,
            "at": self.at.isoformat() if self.at else None,
            "status": self.status,
            "related": self.related,
        }


@dataclass
class UnauthorizedCopy:
    id: str
    origin_delivery: str
    destination: str
    detail: str
    at: datetime | None = None
    status: str = "to_recall"

    def as_dict(self):
        return {
            "id": self.id,
            "origin_delivery": self.origin_delivery,
            "destination": self.destination,
            "detail": self.detail,
            "at": self.at.isoformat() if self.at else None,
            "status": self.status,
        }
