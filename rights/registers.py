"""台账载入。

负责把 ``fixtures/registers.json`` 的形状读成领域对象，并容忍带缺省字段的
扩展写法。载入不做业务判断，判断集中在 :mod:`rights.service`。
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .entities import (
    Authorization,
    DeliveryScope,
    DirectPermission,
    Edit,
    EditVersion,
    Face,
    Source,
    Span,
)
from .errors import ValidationError


def parse_date(value: Any) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def parse_datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    result = datetime.fromisoformat(text)
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def _spans(raw: Any) -> tuple[Span, ...]:
    spans = []
    for item in raw or ():
        clip, start, end = item
        span = Span(str(clip), int(start), int(end))
        if span.start < 0 or span.end < span.start:
            raise ValidationError(f"区间无效：{item}")
        spans.append(span)
    return tuple(spans)


def _uses(raw: Any) -> frozenset[str]:
    if raw is None:
        return frozenset()
    if isinstance(raw, str):
        return frozenset({raw})
    return frozenset(str(v) for v in raw)


class RegisterBook:
    """内存台账。查询只读，修改必须经过服务层。"""

    def __init__(self) -> None:
        self.sources: dict[str, Source] = {}
        self.authorizations: dict[str, Authorization] = {}
        self.edits: dict[str, Edit] = {}
        self.partners: list[str] = []
        self.delivery_scopes: list[DeliveryScope] = []
        self.direct_permissions: list[DirectPermission] = []
        self.activity_day: date | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RegisterBook":
        if not isinstance(raw, dict):
            raise ValidationError("台账根对象应为 JSON 对象")
        book = cls()
        book.activity_day = parse_date(raw.get("activity_day"))
        for source_id, data in (raw.get("sources") or {}).items():
            length = int(data.get("length_ms", 0))
            faces = []
            for item in data.get("faces") or ():
                person, start, end = item
                face = Face(str(person), int(start), int(end))
                if face.start < 0 or face.end < face.start or face.end > length:
                    raise ValidationError(f"原片 {source_id} 的人物区间越界：{item}")
                faces.append(face)
            book.sources[str(source_id)] = Source(str(source_id), length, tuple(faces))

        permissions = raw.get("permissions")
        if permissions is None:
            permissions = raw.get("authorizations") or []
        for index, data in enumerate(permissions, 1):
            person = str(data["person"])
            auth_id = str(data.get("authorization") or f"auth:{person}:{index}")
            if auth_id in book.authorizations:
                raise ValidationError(f"授权编号重复：{auth_id}")
            book.authorizations[auth_id] = Authorization(
                id=auth_id,
                person=person,
                uses=_uses(data.get("uses")),
                valid_from=parse_date(data.get("valid_from")),
                until=parse_date(data.get("until")),
                origin=str(data.get("origin") or "register"),
            )

        for edit_id, data in (raw.get("edits") or {}).items():
            edit = Edit(str(edit_id))
            version_id = str(data.get("version") or edit_id)
            version = EditVersion(
                id=version_id,
                edit=str(edit_id),
                kind=str(data.get("kind") or "video"),
                uses=_uses(data.get("uses")),
                spans=_spans(data.get("spans")),
                created_by=data.get("created_by"),
                created_at=parse_datetime(data.get("created_at")),
                derived_from=data.get("derived_from"),
            )
            if data.get("verified_masks"):
                version.verified_masks = tuple(
                    (str(person), _mask_clip(version, start, end), int(start), int(end))
                    for person, start, end in data["verified_masks"]
                )
            edit.versions[version.id] = version
            edit.current_version = version.id
            book.edits[edit.id] = edit

        book.partners = [str(name) for name in raw.get("partners") or ()]

        for index, data in enumerate(raw.get("delivery_scope") or [], 1):
            book.delivery_scopes.append(
                DeliveryScope(
                    id=str(data.get("id") or f"scope:{index}"),
                    source=str(data["from"]),
                    target=str(data["to"]),
                    edit=str(data["edit"]),
                    use=str(data.get("use") or ""),
                    version=data.get("version"),
                    can_forward=bool(data.get("can_forward", False)),
                    valid_from=parse_date(data.get("valid_from") or data.get("scope_from")),
                    until=parse_date(data.get("scope_until") or data.get("valid_until")),
                )
            )

        for index, data in enumerate(raw.get("direct_permissions") or [], 1):
            book.direct_permissions.append(
                DirectPermission(
                    id=str(data.get("id") or f"direct:{index}"),
                    person=str(data["person"]),
                    channel=str(data["channel"]),
                    # 台账的 version 是成品版本；同一成品可有多个版本记录。
                    version=_direct_version(data),
                    use=str(data.get("use") or ""),
                    valid_from=parse_date(data.get("valid_from")),
                    until=parse_date(data.get("until")),
                )
            )
        return book

    @classmethod
    def from_file(cls, path: Path | str) -> "RegisterBook":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _mask_clip(version: EditVersion, start: int, end: int) -> str:
    """把只带时点的遮挡映射回该剪辑里覆盖它的原片区间。"""
    candidates = [s for s in version.spans if s.start <= start and end <= s.end]
    if candidates:
        return candidates[0].clip
    return version.spans[0].clip if version.spans else ""


def _direct_version(data: dict[str, Any]) -> str:
    """直接许可里的 ``version`` 既可能是成品编号，也可能是具体版本编号。

    载入时保留原文；匹配时由服务层同时尝试成品当前版本与具体版本编号。
    """
    return str(data.get("version") or data.get("edit") or "")

