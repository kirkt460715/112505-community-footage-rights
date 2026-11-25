"""授权判定与画面可见区间的纯函数。

这里不修改任何状态，只回答两个问题：

1. 某人在某个剪辑版本里，去掉了有效遮挡后还剩哪些可见区间；
2. 某个使用场景在某时点有没有仍然有效的授权依据。

``clip`` 内的时间坐标均为原片毫秒。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .entities import (
    Authorization,
    DirectPermission,
    EditVersion,
    Mask,
    Review,
    Source,
)


@dataclass(frozen=True)
class Segment:
    span_index: int
    clip: str
    start: int
    end: int

    def as_dict(self):
        return {
            "span_index": self.span_index,
            "clip": self.clip,
            "start": self.start,
            "end": self.end,
        }


def source_persons_in_span(source: Source | None, start: int, end: int) -> set[str]:
    if source is None:
        return set()
    return {face.person for face in source.faces_in(start, end)}


def segments_for_person(version: EditVersion, source: Source, person: str) -> list[Segment]:
    segments: list[Segment] = []
    for index, span in enumerate(version.spans):
        if span.clip != source.id:
            continue
        for face in source.faces:
            if face.person != person:
                continue
            start, end = max(face.start, span.start), min(face.end, span.end)
            if start < end:
                segments.append(Segment(index, span.clip, start, end))
    return segments


def _subtract(segment: Segment, masks: Iterable[Mask]) -> list[Segment]:
    pieces = [(segment.start, segment.end)]
    for mask in sorted(masks, key=lambda m: (m.start, m.end)):
        # ``verify_clear`` 是“确认这里没有此人”，不构成遮挡。
        if mask.clip != segment.clip or mask.method == "verify_clear":
            continue
        next_pieces = []
        for start, end in pieces:
            if mask.end <= start or end <= mask.start:
                next_pieces.append((start, end))
                continue
            if start < mask.start:
                next_pieces.append((start, mask.start))
            if mask.end < end:
                next_pieces.append((mask.end, end))
        pieces = next_pieces
    return [
        Segment(segment.span_index, segment.clip, start, end)
        for start, end in pieces
        if start < end
    ]


def visible_segments(
    version: EditVersion,
    source: Source,
    person: str,
    masks: Iterable[Mask] = (),
) -> list[Segment]:
    """人物在版本内去掉遮挡后仍可见的区间。"""
    applicable = [
        m
        for m in masks
        if m.person == person and m.span_index is not None
    ]
    result: list[Segment] = []
    for segment in segments_for_person(version, source, person):
        relevant = [m for m in applicable if m.span_index == segment.span_index]
        result.extend(_subtract(segment, relevant))
    return result


def review_masks(review: Review, version: EditVersion, person: str | None = None) -> list[Mask]:
    """只返回该审核确实审到、且确实构成遮挡的区间。

    遮挡只对审片人员实际审到的版本与片段有效；``verify_clear`` 是“确认这里
    没有此人”的说明，不构成遮挡。
    """
    allowed = set(review.scope_indices)
    result = []
    for mask in review.masks:
        if mask.method == "verify_clear":
            continue
        if not (0 <= mask.span_index < len(version.spans)):
            continue
        span = version.spans[mask.span_index]
        if mask.span_index not in allowed:
            continue
        if person is not None and mask.person != person:
            continue
        if mask.clip != span.clip or not span.contains(mask.start, mask.end) or mask.end <= mask.start:
            continue
        result.append(mask)
    return result


def _valid_window(valid_from, until, at: datetime) -> bool:
    day = at.date()
    if valid_from and day < valid_from:
        return False
    if until and day > until:
        return False
    return True


def authorization_basis(
    authorizations: Iterable[Authorization],
    person: str,
    use: str,
    at: datetime,
    *,
    is_revoked=None,
) -> list[Authorization]:
    """在该时点覆盖该用途、且未被撤回的基础授权。"""
    result = []
    for authorization in authorizations:
        if authorization.person != person or use not in authorization.uses:
            continue
        if not _valid_window(authorization.valid_from, authorization.until, at):
            continue
        if is_revoked is not None and is_revoked(authorization.id, use, at):
            continue
        result.append(authorization)
    return result


def direct_basis(
    direct_permissions: Iterable[DirectPermission],
    person: str,
    use: str,
    channel: str,
    version: str,
    at: datetime,
) -> list[DirectPermission]:
    """授权人单独给某渠道、某版本的同用途许可。"""
    return [
        permission
        for permission in direct_permissions
        if permission.person == person
        and permission.use == use
        and permission.channel == channel
        and permission.version == version
        and _valid_window(permission.valid_from, permission.until, at)
    ]
