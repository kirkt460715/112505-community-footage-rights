"""业务服务：编辑送审、人物授权审核、合作方发布与撤回。

设计要点
--------

* 审查记录绑定到具体剪辑版本（及版本内容指纹）。换版本或换静帧后，旧记录
  仍可追溯，但不会被套用到新版本上。
* 遮挡只对审片人员实际审到的区间、且只对审到的版本有效。
* 授权按人物、用途、时段判定；一次撤回只终止被指名的那条授权的那一种用途。
* 每次发布都记录交付编号、渠道与父交付，因而可以从任一级追到实际转载端。
* 对端回执按（操作, 接收方）返回事实；回执未达时用同一编号重试，不生成新请求。
* 查询面按角色裁剪：渠道只看自己的内容，编辑只拿审片所需的授权范围。

人物编号都是演练用编号；服务不接收、也不返回任何身份证明材料。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from . import analysis
from .clock import Clock, SystemClock
from .common import (
    at_minute,
    delivery_chain,
    descendants,
    message_time,
    sanitize_identifier,
    to_datetime,
)
from .entities import (
    Annotation,
    Authorization,
    Delivery,
    DeliveryScope,
    DirectPermission,
    Edit,
    EditVersion,
    Face,
    HandlingRequest,
    Mask,
    Revocation,
    Review,
    Source,
    Span,
    UnauthorizedCopy,
    Violation,
)
from .errors import Conflict, Forbidden, NotFound, RightsError, ValidationError
from .model import INTERNAL_USES, DeliveryState, METHODS, ReviewState, Role
from .registers import RegisterBook, parse_date
from .security import Actor, require, require_channel
from .store import Store
from .transport import InMemoryReceiptTransport, LostReply, ReceiptTransport



def _iso(value) -> str | None:
    return None if value is None else value.isoformat()


class RightsService:
    """可复用的业务后端。除构造外，所有写入都经过角色检查。"""

    def __init__(
        self,
        registers: RegisterBook | dict,
        *,
        clock: Clock | None = None,
        transport: ReceiptTransport | None = None,
        receipts: Iterable[dict] | None = None,
    ):
        book = registers if isinstance(registers, RegisterBook) else RegisterBook.from_dict(registers)
        self.store = Store(book=book)
        self.clock = clock or SystemClock()
        if transport is None and receipts is not None:
            transport = InMemoryReceiptTransport(receipts)
        self.transport = transport
        self._seed_reviews()

    # ------------------------------------------------------------------ 构造

    @classmethod
    def from_fixtures(
        cls,
        folder: Path | str,
        *,
        clock: Clock | None = None,
        transport: ReceiptTransport | None = None,
        receipts: Iterable[dict] | None = None,
    ) -> "RightsService":
        folder = Path(folder)
        book = RegisterBook.from_file(folder / "registers.json")
        if receipts is None and (folder / "receipts.json").exists():
            receipts = json.loads((folder / "receipts.json").read_text(encoding="utf-8"))
        return cls(book, clock=clock, transport=transport, receipts=receipts)

    def _seed_reviews(self) -> None:
        """台账里已完成的可信遮挡审查作为只读种子记录。"""
        for edit in self.store.book.edits.values():
            for version in edit.versions.values():
                if not version.verified_masks:
                    continue
                annotations = {
                    index: Annotation(index, self._span_persons(version, index), True)
                    for index in range(len(version.spans))
                }
                masks = []
                for person, clip, start, end in version.verified_masks:
                    index = self._span_index(version, clip, start, end)
                    if index is None:
                        raise ValidationError(f"台账遮挡不在剪辑范围内：{clip} {start}-{end}")
                    masks.append(Mask(person, clip, start, end, "mask", index))
                review = Review(
                    id=f"seed-{edit.id}-{version.id}",
                    edit=edit.id,
                    version=version.id,
                    kind=version.kind,
                    state=ReviewState.APPROVED,
                    scope_indices=tuple(range(len(version.spans))),
                    annotations=annotations,
                    masks=masks,
                    fingerprint=version.fingerprint(),
                    trusted=True,
                    seed=True,
                    reviewed_at=self.clock.now(),
                    note="台账载入的可信遮挡审查",
                )
                self.store.reviews[review.id] = review
                self.store.review_order.append(review.id)

    # ------------------------------------------------------------- 查询小工具

    def _book(self) -> RegisterBook:
        return self.store.book

    def _edit(self, edit_id: str) -> Edit:
        edit = self._book().edits.get(edit_id)
        if edit is None:
            raise NotFound(f"没有该剪辑：{edit_id}", code="unknown_edit")
        return edit

    def _version(self, edit_id: str, version_id: str | None = None) -> EditVersion:
        edit = self._edit(edit_id)
        version = edit.version(version_id)
        if version is None:
            raise NotFound(f"没有该剪辑版本：{edit_id}/{version_id}", code="unknown_version")
        return version

    def _span_persons(self, version: EditVersion, index: int) -> tuple[str, ...]:
        span = version.spans[index]
        source = self._book().sources.get(span.clip)
        return tuple(sorted(analysis.source_persons_in_span(source, span.start, span.end)))

    @staticmethod
    def _span_index(version: EditVersion, clip: str, start: int, end: int) -> int | None:
        for index, span in enumerate(version.spans):
            if span.clip == clip and span.contains(start, end):
                return index
        return None

    def _persons_in_version(self, version: EditVersion) -> set[str]:
        persons = set()
        for span in version.spans:
            source = self._book().sources.get(span.clip)
            persons |= analysis.source_persons_in_span(source, span.start, span.end)
        return persons

    def _revealed(self, version: EditVersion, review: Review | None, person: str):
        """该版本在有效遮挡之后仍露出该人物的区间。"""
        segments = []
        masks = analysis.review_masks(review, version, person) if review else []
        for clip in {span.clip for span in version.spans}:
            source = self._book().sources.get(clip)
            if source is None:
                continue
            segments.extend(analysis.visible_segments(version, source, person, masks))
        return segments

    def _revoked(self, authorization_id: str, use: str, at: datetime) -> bool:
        return any(
            revocation.authorization == authorization_id
            and revocation.use == use
            and revocation.at <= at
            for revocation in self.store.revocations.values()
        )

    def _base_permission(self, person: str, use: str, at: datetime):
        return analysis.authorization_basis(
            self._book().authorizations.values(),
            person,
            use,
            at,
            is_revoked=lambda auth_id, target_use, moment: self._revoked(
                auth_id, target_use, moment
            ),
        )

    def _direct_permission(self, person, use, channel, version, at, *, edit=None):
        """授权人单独给某渠道、某版本的同用途许可。

        ``version`` 精确匹配版本编号；台账里若写的是成品编号而该成品只有
        一个版本，载入时已把成品编号当作版本编号。不同版本（例如由视频换
        成的静帧）不能继承原版本的直接许可。
        """
        return analysis.direct_basis(
            [*self._book().direct_permissions, *self.store.extra_direct],
            person,
            use,
            channel,
            version,
            at,
        )

    def _active_review(self, edit: str, version: str) -> Review | None:
        for review_id in reversed(self.store.review_order):
            review = self.store.reviews[review_id]
            if review.edit == edit and review.version == version and review.active():
                return review
        return None

    def _review_for_delivery(self, delivery: Delivery) -> Review | None:
        if delivery.review_id:
            review = self.store.reviews.get(delivery.review_id)
            if review is not None and review.version == delivery.version:
                return review
        return self._active_review(delivery.edit, delivery.version)

    def _version_payload(self, version: EditVersion) -> dict:
        return {
            "edit": version.edit,
            "version": version.id,
            "kind": version.kind,
            "uses": sorted(version.uses),
            "spans": [span.as_list() for span in version.spans],
            "created_by": version.created_by,
            "created_at": _iso(version.created_at),
            "derived_from": version.derived_from,
        }

    def _review_payload(self, review: Review) -> dict:
        edit = self._book().edits.get(review.edit)
        current = edit.current_version if edit else None
        return {
            "id": review.id,
            "edit": review.edit,
            "version": review.version,
            "kind": review.kind,
            "state": review.state.value,
            "trusted": review.trusted,
            "seed": review.seed,
            "internal_only": review.internal_only,
            "current_version": current,
            "applies_to_current_version": review.version == current,
            "scope_indices": list(review.scope_indices),
            "annotations": [
                {
                    "span_index": annotation.span_index,
                    "persons": list(annotation.persons),
                    "recognized": annotation.recognized,
                    "note": annotation.note,
                }
                for annotation in review.annotations.values()
            ],
            "masks": [mask.as_dict() for mask in review.masks],
            "submitted_by": review.submitted_by,
            "submitted_at": _iso(review.submitted_at),
            "reviewed_by": review.reviewed_by,
            "reviewed_at": _iso(review.reviewed_at),
            "superseded_by": review.superseded_by,
            "note": review.note,
        }

    def _delivery_payload(self, delivery: Delivery) -> dict:
        return {
            "id": delivery.id,
            "edit": delivery.edit,
            "version": delivery.version,
            "channel": delivery.channel,
            "use": delivery.use,
            "parent_delivery": delivery.parent_delivery,
            "chain": delivery_chain(self.store.deliveries, delivery),
            "state": delivery.state.value,
            "published_at": _iso(delivery.published_at),
            "received_at": _iso(delivery.received_at),
            "review_id": delivery.review_id,
            "authorized_scope": delivery.authorized_scope,
            "copies_withdrawn": delivery.copies_withdrawn,
            "still_displayed": list(delivery.still_displayed),
            "created_by": delivery.created_by,
            "notes": list(delivery.notes),
        }

    # --------------------------------------------------------------- 台账登记

    def register_source(self, source_id, length_ms, faces=(), *, actor=None):
        require(actor, "register_source")
        if source_id in self._book().sources:
            raise Conflict(f"原片已登记：{source_id}")
        entries = tuple(Face(str(p), int(s), int(e)) for p, s, e in faces)
        self._book().sources[source_id] = Source(source_id, int(length_ms), entries)
        return {"id": source_id, "length_ms": int(length_ms),
                "faces": [list(face) for face in faces]}

    def register_authorization(
        self, person, uses, *, authorization=None, valid_from=None, until=None, actor=None
    ):
        require(actor, "revoke")
        auth_id = authorization or f"auth:{person}:{len(self._book().authorizations) + 1}"
        if auth_id in self._book().authorizations:
            raise Conflict(f"授权编号重复：{auth_id}")
        record = Authorization(
            auth_id, str(person), frozenset(uses), parse_date(valid_from), parse_date(until)
        )
        self._book().authorizations[auth_id] = record
        return {
            "authorization": auth_id,
            "person": person,
            "uses": sorted(record.uses),
            "valid_from": _iso(record.valid_from),
            "until": _iso(record.until),
        }

    def grant_direct_permission(
        self, person, channel, version, use, *, valid_from=None, until=None, actor=None
    ):
        require(actor, "revoke")
        permission = DirectPermission(
            f"direct:{person}:{channel}:{version}:{use}",
            str(person), str(channel), str(version), str(use),
            parse_date(valid_from), parse_date(until),
        )
        self.store.extra_direct.append(permission)
        return {
            "person": person, "channel": channel, "version": version, "use": use,
            "until": _iso(permission.until),
        }

    def grant_delivery_scope(
        self, source, target, edit, use, *, version=None, can_forward=False,
        valid_from=None, until=None, actor=None,
    ):
        require(actor, "grant_scope")
        for existing in self._book().delivery_scopes:
            if (existing.source, existing.target, existing.edit, existing.use) == (
                source, target, edit, use
            ) and existing.version == version:
                raise Conflict("相同转载许可已存在", details={"id": existing.id})
        scope = DeliveryScope(
            f"scope:{source}:{target}:{edit}:{len(self._book().delivery_scopes) + 1}",
            str(source), str(target), str(edit), str(use), version, bool(can_forward),
            parse_date(valid_from), parse_date(until),
        )
        self._book().delivery_scopes.append(scope)
        return {
            "id": scope.id, "from": scope.source, "to": scope.target, "edit": scope.edit,
            "use": scope.use, "version": scope.version,
            "can_forward": scope.can_forward, "until": _iso(scope.until),
        }

    # ----------------------------------------------------------------- 剪辑

    def create_version(
        self, edit_id, *, kind, uses, spans, version=None, derived_from=None, actor=None,
    ) -> dict:
        require(actor, "create_version")
        edit = self._book().edits.get(edit_id)
        if edit is None:
            edit = Edit(edit_id)
            self._book().edits[edit_id] = edit
        version_id = version or f"{edit_id}@{len(edit.versions) + 1}"
        if version_id in edit.versions:
            raise Conflict(f"版本已存在：{version_id}", code="duplicate_version")
        parsed = []
        for item in spans:
            clip, start, end = item
            source = self._book().sources.get(clip)
            if source is None:
                raise ValidationError(f"引用了未登记的原片：{clip}")
            span = Span(str(clip), int(start), int(end))
            if span.start < 0 or span.end <= span.start or span.end > source.length_ms:
                raise ValidationError(
                    f"区间越界：{item}", details={"length_ms": source.length_ms}
                )
            parsed.append(span)
        if not parsed:
            raise ValidationError("剪辑至少需要一个原片区间")
        record = EditVersion(
            version_id, edit_id, str(kind), frozenset(uses), tuple(parsed),
            created_by=None if actor is None else actor.name,
            created_at=self.clock.now(),
            derived_from=derived_from,
        )
        previous = edit.current_version
        edit.versions[version_id] = record
        edit.current_version = version_id
        result = self._version_payload(record)
        result["previous_version"] = previous
        result["supersedes_review"] = self._active_review(edit_id, previous) is not None if previous else False
        return result

    def list_edits(self, *, actor=None) -> list[dict]:
        return [
            {
                "edit": edit.id,
                "current_version": edit.current_version,
                "versions": [self._version_payload(v) for v in edit.versions.values()],
            }
            for edit in self._book().edits.values()
        ]

    def editor_brief(self, edit_id=None, version_id=None, *, actor=None) -> dict:
        """编辑视角：只返回审片需要的授权范围，不含身份材料。"""
        require(actor, "read_brief")
        targets = (
            [self._version(edit_id, version_id)]
            if edit_id
            else [v for edit in self._book().edits.values() for v in edit.versions.values()]
        )
        items = []
        for version in targets:
            persons = []
            for person in sorted(self._persons_in_version(version)):
                permissions = [
                    {
                        "authorization": authorization.id,
                        "uses": sorted(authorization.uses),
                        "valid_from": _iso(authorization.valid_from),
                        "until": _iso(authorization.until),
                    }
                    for authorization in self._book().authorizations.values()
                    if authorization.person == person
                ]
                segments = [
                    segment.as_dict()
                    for clip in sorted({s.clip for s in version.spans})
                    for segment in self._visible_without_review(version, clip, person)
                ]
                persons.append(
                    {"person": person, "authorizations": permissions, "segments": segments}
                )
            review = self._active_review(version.edit, version.id)
            items.append(
                {
                    "edit": version.edit,
                    "version": version.id,
                    "kind": version.kind,
                    "uses": sorted(version.uses),
                    "spans": [span.as_list() for span in version.spans],
                    "persons": persons,
                    "review": None if review is None else self._review_payload(review),
                }
            )
        return {"items": items}

    def _visible_without_review(self, version, clip, person):
        source = self._book().sources.get(clip)
        return [] if source is None else analysis.visible_segments(version, source, person, [])

    def edit_history(self, edit_id, *, actor=None) -> dict:
        """原稿与收回经过：换版本后旧版本、旧审核、旧交付与撤回都仍可查。"""
        require(actor, "read_internal")
        edit = self._edit(edit_id)
        deliveries = [
            self._delivery_payload(self.store.deliveries[did])
            for did in self.store.delivery_order
            if self.store.deliveries[did].edit == edit_id
        ]
        persons = {
            person
            for version in edit.versions.values()
            for person in self._persons_in_version(version)
        }
        revocations = [
            self._revocation_payload(revocation)
            for revocation in self.store.revocations.values()
            if revocation.person in persons
        ]
        return {
            "edit": edit.id,
            "current_version": edit.current_version,
            "versions": [self._version_payload(v) for v in edit.versions.values()],
            "reviews": [
                self._review_payload(review)
                for review in self.store.reviews.values()
                if review.edit == edit_id
            ],
            "deliveries": deliveries,
            "revocations": revocations,
            "violations": [
                v.as_dict() for v in self.store.violations.values()
                if v.delivery in {d["id"] for d in deliveries}
            ],
        }

    # ----------------------------------------------------------------- 审片

    def submit_review(self, edit_id, *, version=None, scope=None, actor=None) -> dict:
        require(actor, "submit_review")
        version_record = self._version(edit_id, version)
        indices = self._normalize_scope(version_record, scope)
        review = Review(
            id=self.store.next_id("review"),
            edit=edit_id,
            version=version_record.id,
            kind=version_record.kind,
            state=ReviewState.IN_REVIEW,
            scope_indices=indices,
            submitted_by=None if actor is None else actor.name,
            submitted_at=self.clock.now(),
            fingerprint=version_record.fingerprint(),
        )
        self.store.reviews[review.id] = review
        self.store.review_order.append(review.id)
        return self._review_payload(review)

    @staticmethod
    def _normalize_scope(version: EditVersion, scope) -> tuple[int, ...]:
        if scope in (None, [], ()):
            return tuple(range(len(version.spans)))
        indices = []
        for item in scope:
            index = int(item)
            if not 0 <= index < len(version.spans):
                raise ValidationError(f"送审区间越界：{item}")
            indices.append(index)
        if not indices:
            raise ValidationError("送审区间不能为空")
        return tuple(sorted(set(indices)))

    def annotate(
        self, review_id, span_index, persons, *, recognized=True, note=None, actor=None
    ) -> dict:
        require(actor, "annotate")
        review = self._review(review_id)
        index = int(span_index)
        if index not in review.scope_indices:
            raise ValidationError("只能注记本次送审范围内的片段", details={"span_index": index})
        if review.state not in {ReviewState.IN_REVIEW, ReviewState.PENDING}:
            raise Conflict("该审核已结束，不能补注记", code="review_closed")
        clean = tuple(sorted({str(person) for person in persons}))
        if recognized and not clean:
            raise ValidationError("已认清的片段应注明至少一个人物")
        review.annotations[index] = Annotation(index, clean, bool(recognized), note)
        return self._review_payload(review)

    def add_mask(
        self, review_id, person, span_index, start, end, *, method="mask", actor=None
    ) -> dict:
        require(actor, "annotate")
        review = self._review(review_id)
        if method not in METHODS:
            raise ValidationError(f"未知处置方式：{method}")
        index = int(span_index)
        if index not in review.scope_indices:
            raise ValidationError("遮挡只能落在本次审到的片段上", details={"span_index": index})
        version = self._version(review.edit, review.version)
        span = version.spans[index]
        start, end = int(start), int(end)
        if not span.contains(start, end) or end <= start:
            raise ValidationError(
                "遮挡范围超出已审片段",
                details={"span": span.as_list(), "start": start, "end": end},
            )
        mask = Mask(str(person), span.clip, start, end, str(method), index)
        review.masks = [
            existing
            for existing in review.masks
            if not (existing.person == mask.person and existing.span_index == index
                    and existing.start == start and existing.end == end)
        ]
        review.masks.append(mask)
        return self._review_payload(review)

    def approve_review(self, review_id, *, actor=None) -> dict:
        require(actor, "approve_review")
        review = self._review(review_id)
        if review.state is ReviewState.APPROVED:
            return self._review_payload(review)
        if review.state is ReviewState.REJECTED:
            raise Conflict("已驳回的审核不能直接通过", code="review_rejected")
        missing = [i for i in review.scope_indices if i not in review.annotations]
        if missing:
            raise ValidationError("尚有送审片段未注明人物", details={"span_indices": missing})
        version = self._version(review.edit, review.version)
        if review.fingerprint != version.fingerprint():
            raise Conflict("剪辑内容已变化，请重新送审", code="review_version_mismatch")
        review.state = ReviewState.APPROVED
        review.reviewed_by = None if actor is None else actor.name
        review.reviewed_at = self.clock.now()
        review.trusted = True
        review.internal_only = any(
            not annotation.recognized for annotation in review.annotations.values()
        )
        if review.internal_only:
            review.note = (review.note + "；" if review.note else "") + "存在未认清人物，仅供内部审核"
        return self._review_payload(review)

    def reject_review(self, review_id, *, reason=None, actor=None) -> dict:
        require(actor, "reject_review")
        review = self._review(review_id)
        review.state = ReviewState.REJECTED
        review.reviewed_by = None if actor is None else actor.name
        review.reviewed_at = self.clock.now()
        review.note = reason
        return self._review_payload(review)

    def _review(self, review_id) -> Review:
        review = self.store.reviews.get(review_id)
        if review is None:
            raise NotFound(f"没有该审核：{review_id}", code="unknown_review")
        return review

    def get_review(self, review_id, *, actor=None) -> dict:
        return self._review_payload(self._review(review_id))

    def list_reviews(self, *, edit=None, version=None, actor=None) -> list[dict]:
        return [
            self._review_payload(review)
            for review in self.store.reviews.values()
            if (edit is None or review.edit == edit)
            and (version is None or review.version == version)
        ]

    def _publishable_review(self, edit_id, version: EditVersion) -> Review:
        review = self._active_review(edit_id, version.id)
        if review is None:
            raise Conflict("该版本没有可用的审片记录", code="review_required")
        if review.fingerprint != version.fingerprint():
            raise Conflict("剪辑内容已变化，请重新送审", code="review_version_mismatch")
        unreviewed = self._unreviewed_spans(version, review)
        if unreviewed:
            raise Conflict(
                "该版本仍有未审到的含人物片段，不能发布",
                code="review_scope_incomplete",
                details={"span_indices": unreviewed},
            )
        return review

    def _unreviewed_spans(self, version: EditVersion, review: Review) -> list[int]:
        """画面里有人、但本次审核没有审到的片段，不能当作已审。"""
        covered = set(review.scope_indices)
        return [
            index
            for index in range(len(version.spans))
            if index not in covered and self._span_persons(version, index)
        ]

    def review_scope_check(self, review_id, *, actor=None) -> dict:
        review = self._review(review_id)
        version = self._version(review.edit, review.version)
        unreviewed = self._unreviewed_spans(version, review)
        return {
            "review": review.id,
            "version": review.version,
            "reviewed_span_indices": list(review.scope_indices),
            "unreviewed_person_spans": unreviewed,
            "publishable": not unreviewed and review.state is ReviewState.APPROVED,
        }

    # ----------------------------------------------------------------- 发布

    def publish(
        self, edit_id, channel, *, version=None, use=None, delivery=None,
        parent_delivery=None, at=None, actor=None,
    ) -> dict:
        require(actor, "publish")
        version_record = self._version(edit_id, version)
        if use:
            if use not in version_record.uses:
                raise ValidationError(f"该版本不适用于用途 {use}")
            chosen_use = str(use)
        elif version_record.uses:
            chosen_use = sorted(version_record.uses)[0]
        else:
            raise ValidationError("该版本未声明适用用途")
        published_at = to_datetime(at, self.clock.now())
        review = self._publishable_review(edit_id, version_record)
        assessment = self.assess(version_record, chosen_use, published_at, review=review)
        direct = self._direct_permissions_for(
            version_record, chosen_use, channel, published_at, assessment["revealed"], edit_id
        )
        unresolved = [
            person for person in assessment["revealed"]
            if not self._covered(person, assessment, direct)
        ]
        internal = chosen_use in INTERNAL_USES
        if review.internal_only and not internal:
            raise Forbidden(
                "存在未认清人物，只能内部审核，不得交给公共渠道",
                code="internal_only_review",
                details={"review": review.id},
            )
        # 内部用途且审核中确有无法认清的人物时，可以继续内部留用；
        # 其余情况仍要求逐人逐用途的授权。
        if unresolved and not (internal and review.internal_only):
            raise Forbidden(
                "缺少覆盖该渠道、版本与用途的授权",
                code="authorization_missing",
                details={"persons": unresolved, "use": chosen_use},
            )
        scope = None
        if parent_delivery:
            scope = self._check_onward(
                parent_delivery, channel, edit_id, version_record, chosen_use, published_at
            )
        delivery_id = self._new_delivery_id(delivery)
        record = Delivery(
            id=delivery_id,
            edit=edit_id,
            version=version_record.id,
            channel=str(channel),
            use=chosen_use,
            parent_delivery=parent_delivery,
            state=DeliveryState.PUBLISHED,
            published_at=published_at,
            received_at=self.clock.now(),
            review_id=review.id,
            authorized_scope=None if scope is None else scope.id,
            created_by=None if actor is None else actor.name,
            created_at=self.clock.now(),
        )
        self._save_delivery(record)
        payload = self._delivery_payload(record)
        payload["assessment"] = self._assessment_payload(assessment, direct, unresolved, scope)
        if unresolved and internal:
            payload["notes"].append("内部用途：授权未覆盖 " + ",".join(unresolved))
        return payload

    def _new_delivery_id(self, requested):
        if requested:
            delivery_id = sanitize_identifier(str(requested))
            if delivery_id in self.store.deliveries:
                raise Conflict(f"交付编号已存在：{delivery_id}", code="duplicate_delivery")
            return delivery_id
        counter = len(self.store.deliveries) + 1
        while f"d-{counter:03d}" in self.store.deliveries:
            counter += 1
        return f"d-{counter:03d}"

    def _save_delivery(self, record: Delivery):
        self.store.deliveries[record.id] = record
        self.store.delivery_order.append(record.id)

    def _direct_permissions_for(self, version, use, channel, at, persons, edit_id):
        found = []
        for person in persons:
            found.extend(
                self._direct_permission(
                    person, use, str(channel), version.id, at, edit=edit_id
                )
            )
        return found

    @staticmethod
    def _covered(person, assessment, direct) -> bool:
        if assessment["basis"].get(person) == "authorized":
            return True
        return any(permission.person == person for permission in direct)

    def _check_onward(self, parent_delivery, channel, edit_id, version, use, at):
        parent = self.store.deliveries.get(parent_delivery)
        if parent is None:
            raise NotFound(f"父交付不存在：{parent_delivery}", code="unknown_parent")
        if str(channel) == parent.channel:
            raise ValidationError("再转递的接收方不能与来源相同")
        candidates = [
            scope
            for scope in self._book().delivery_scopes
            if scope.matches(
                source=parent.channel, target=str(channel), edit=edit_id, use=use,
                version=version.id, at=at,
            )
        ]
        if not candidates:
            # 上游许可若明确允许再次转递，接收方可以向前再传一层。
            candidates = [
                scope
                for scope in self._book().delivery_scopes
                if scope.can_forward
                and scope.target == parent.channel
                and scope.edit == edit_id
                and scope.use == use
                and (scope.version is None or scope.version == version.id)
                and scope.within_window(at)
            ]
        if not candidates:
            raise Forbidden(
                "来源渠道没有向该渠道再转递的许可",
                code="onward_not_permitted",
                details={"from": parent.channel, "to": str(channel)},
            )
        return candidates[0]

    def assess(self, version: EditVersion, use: str, at: datetime, *, review=None):
        """评估一个版本在指定用途、时点下的可见人物与授权状态。"""
        if review is None:
            review = self._active_review(version.edit, version.id)
        if review is not None and review.fingerprint != version.fingerprint():
            review = None
        persons = sorted(self._persons_in_version(version))
        revealed, masked, basis = [], [], {}
        for person in persons:
            segments = self._revealed(version, review, person)
            if not segments:
                masked.append(person)
                continue
            revealed.append(person)
            basis[person] = "authorized" if self._base_permission(person, use, at) else "unauthorized"
        return {
            "edit": version.edit,
            "version": version.id,
            "use": use,
            "at": at,
            "review_id": None if review is None else review.id,
            "review_state": None if review is None else review.state.value,
            "internal_only": bool(review and review.internal_only),
            "persons": persons,
            "revealed": revealed,
            "masked": masked,
            "basis": basis,
        }

    def _assessment_payload(self, assessment, direct, unresolved, scope):
        result = {
            "use": assessment["use"],
            "review_id": assessment["review_id"],
            "internal_only": assessment["internal_only"],
            "revealed": assessment["revealed"],
            "masked": assessment["masked"],
            "unresolved": unresolved,
            "direct_permissions": [
                {
                    "person": permission.person,
                    "channel": permission.channel,
                    "version": permission.version,
                    "use": permission.use,
                    "until": _iso(permission.until),
                }
                for permission in direct
            ],
        }
        if scope is not None:
            result["scope"] = {
                "id": scope.id, "from": scope.source, "to": scope.target,
                "version": scope.version, "can_forward": scope.can_forward,
            }
        return result

    def get_delivery(self, delivery_id, *, actor=None) -> dict:
        delivery = self._delivery(delivery_id)
        if actor is not None and actor.is_channel:
            require_channel(actor, delivery.channel)
        return self._delivery_payload(delivery)

    def _delivery(self, delivery_id) -> Delivery:
        delivery = self.store.deliveries.get(delivery_id)
        if delivery is None:
            raise NotFound(f"没有该交付：{delivery_id}", code="unknown_delivery")
        return delivery

    def channel_view(self, channel, *, actor=None) -> dict:
        if actor is not None:
            if actor.is_channel:
                require_channel(actor, channel)
            else:
                require(actor, "read_internal")
        deliveries = [
            self._delivery_payload(self.store.deliveries[did])
            for did in self.store.delivery_order
            if self.store.deliveries[did].channel == channel
        ]
        requests = [
            request.as_dict()
            for request in self.store.requests.values()
            if request.channel == channel
        ]
        recalls = [
            copy.as_dict()
            for copy in self.store.unauthorized.values()
            if copy.origin_delivery in {d["id"] for d in deliveries}
        ]
        return {
            "channel": channel,
            "deliveries": deliveries,
            "requests": requests,
            "recall_copies": recalls,
        }

    def record_publication(self, payload, *, event_minute=None, cursor=None) -> dict:
        """按消息事实登记一次发布；未获准的再转递也登记并留痕。"""
        edit_id = payload.get("edit")
        if not edit_id:
            raise ValidationError("发布消息缺少剪辑编号")
        edit = self._edit(edit_id)
        version = self._version(edit_id, payload.get("version") or edit.current_version)
        day = self._book().activity_day
        published_at = message_time(payload, event_minute, day, self.clock.now())
        received_at = at_minute(day, event_minute, self.clock.now())
        delivery_id = str(payload.get("delivery") or self._new_delivery_id(None))
        if delivery_id in self.store.deliveries:
            existing = self.store.deliveries[delivery_id]
            if existing.source_event is not None and cursor is not None and cursor < existing.source_event:
                raise Conflict("交付编号已存在且来自更早消息", code="duplicate_delivery")
            return self._delivery_payload(existing)
        use = str(payload.get("use") or (sorted(version.uses)[0] if version.uses else ""))
        parent = payload.get("parent_delivery")
        review = self._active_review(edit_id, version.id)
        record = Delivery(
            id=delivery_id,
            edit=edit_id,
            version=version.id,
            channel=str(payload["channel"]),
            use=use,
            parent_delivery=parent,
            state=DeliveryState.PUBLISHED,
            published_at=published_at,
            received_at=received_at,
            review_id=None if review is None else review.id,
            created_by="fixture",
            created_at=self.clock.now(),
        )
        if parent:
            parent_delivery = self.store.deliveries.get(parent)
            if parent_delivery is None:
                raise NotFound(f"父交付不存在：{parent}", code="unknown_parent")
            scopes = [
                scope
                for scope in self._book().delivery_scopes
                if scope.matches(
                    source=parent_delivery.channel, target=str(payload["channel"]),
                    edit=edit_id, use=use, version=version.id, at=published_at,
                )
            ]
            if scopes:
                record.authorized_scope = scopes[0].id
            else:
                record.notes.append("来源渠道无再转递许可")
                self._add_violation(
                    "unauthorized_forward", delivery_id, record.channel,
                    f"未经许可从 {parent_delivery.channel} 再转递", published_at,
                    related=delivery_id,
                )
                self._add_unauthorized_copy(
                    parent, record.channel,
                    f"未经许可再转递，交付 {delivery_id}", published_at,
                    related=delivery_id, with_violation=False,
                )
        if self._person_revoked_before(record, published_at):
            record.notes.append("撤回生效后仍对外发布")
            self._add_violation(
                "distributed_after_revocation", delivery_id, record.channel,
                "撤回生效后仍对外发布", published_at,
            )
        self._save_delivery(record)
        return self._delivery_payload(record)

    def _person_revoked_before(self, delivery: Delivery, moment: datetime) -> bool:
        version = self._book().edits[delivery.edit].version(delivery.version)
        if version is None:
            return False
        review = self._review_for_delivery(delivery)
        for revocation in self.store.revocations.values():
            if revocation.use != delivery.use:
                continue
            if revocation.at > moment:
                continue
            if self._revealed(version, review, revocation.person):
                return True
        return False

    # ----------------------------------------------------------------- 撤回

    def revoke(
        self, *, authorization=None, person=None, use, at=None, actor=None, by=None
    ) -> dict:
        require(actor, "revoke")
        if not use:
            raise ValidationError("撤回需要指明用途")
        record = None
        if authorization:
            record = self._book().authorizations.get(authorization)
            if record is None:
                raise NotFound(f"没有该授权：{authorization}", code="unknown_authorization")
            if person and record.person != person:
                raise ValidationError(
                    "授权编号与人物不一致",
                    details={"authorization": authorization, "person": person},
                )
            person = record.person
        elif person:
            candidates = [a for a in self._book().authorizations.values() if a.person == person]
            if len(candidates) != 1:
                raise ValidationError(
                    "该人物有多个授权，需指明授权编号",
                    details={"authorizations": [c.id for c in candidates]},
                )
            record = candidates[0]
            authorization = record.id
        else:
            raise ValidationError("撤回需要授权编号或人物编号")
        if use not in record.uses:
            raise ValidationError(
                f"授权 {authorization} 不含用途 {use}",
                details={"uses": sorted(record.uses)},
            )
        moment = to_datetime(at, self.clock.now())
        for existing in self.store.revocations.values():
            if (existing.authorization == authorization and existing.use == use
                    and existing.at == moment):
                return self._revocation_payload(existing)
        revocation = Revocation(
            id=self.store.next_id("rev"),
            authorization=authorization,
            person=person,
            use=use,
            at=moment,
            by=by or (None if actor is None else actor.name),
            sequence=len(self.store.revocations) + 1,
        )
        self.store.revocations[revocation.id] = revocation
        self.store.revocation_order.append(revocation.id)
        return self._revocation_payload(revocation)

    def _revocation_payload(self, revocation: Revocation) -> dict:
        return {
            "id": revocation.id,
            "authorization": revocation.authorization,
            "person": revocation.person,
            "use": revocation.use,
            "at": _iso(revocation.at),
            "by": revocation.by,
        }

    def _revocations_for(self, person=None, authorization=None, use=None):
        return [
            revocation
            for revocation in self.store.revocations.values()
            if (person is None or revocation.person == person)
            and (authorization is None or revocation.authorization == authorization)
            and (use is None or revocation.use == use)
        ]

    def impact(self, person, *, use=None, at=None, actor=None) -> dict:
        """以一次人物撤回为入口，查实际影响与责任人。"""
        if actor is not None:
            require(actor, "judge_use")
        revocations = self._revocations_for(person=person, use=use)
        if not revocations:
            raise NotFound(f"没有该人物的撤回记录：{person}", code="no_revocation")
        involved_uses = {use} if use is not None else {r.use for r in revocations}
        moment = to_datetime(at, max(r.at for r in revocations))
        versions = []
        for edit in self._book().edits.values():
            for version in edit.versions.values():
                if person not in self._persons_in_version(version):
                    continue
                review = self._active_review(edit.id, version.id)
                revealed = self._revealed(version, review, person)
                versions.append(
                    {
                        "edit": edit.id,
                        "version": version.id,
                        "kind": version.kind,
                        "uses": sorted(version.uses),
                        "masked": not revealed,
                        "review_id": None if review is None else review.id,
                        "trusted_review": bool(review and review.trusted),
                        "visible_segments": [s.as_dict() for s in revealed],
                        "can_continue": not revealed,
                        "reason": "已由可信审查遮挡" if not revealed else "仍露出该人物",
                    }
                )
        deliveries = []
        for delivery_id in self.store.delivery_order:
            delivery = self.store.deliveries[delivery_id]
            judgement = self.judge_delivery(person, delivery, involved_uses, moment)
            if judgement is not None:
                deliveries.append(judgement)
        return {
            "person": person,
            "at": _iso(moment),
            "revocations": [self._revocation_payload(r) for r in revocations],
            "uses": sorted(involved_uses),
            "versions": versions,
            "deliveries": deliveries,
            "continue": [d["delivery"] for d in deliveries if d["action"] == "continue"],
            "hold": [d["delivery"] for d in deliveries if d["action"] == "hold"],
            "recall": [d["delivery"] for d in deliveries if d["action"] == "recall"],
            "violations": [v.as_dict() for v in self.store.violations.values()],
            "unauthorized_copies": [c.as_dict() for c in self.store.unauthorized.values()],
            "responsible": self._responsible(person, deliveries),
        }

    def judge_delivery(self, person, delivery: Delivery, uses, at: datetime):
        """判断单个交付：继续、暂停新分发或追收。"""
        edit = self._book().edits.get(delivery.edit)
        version = edit.version(delivery.version) if edit else None
        if version is None or person not in self._persons_in_version(version):
            return None
        review = self._review_for_delivery(delivery)
        revealed = self._revealed(version, review, person)
        if not revealed:
            return self._judgement(
                delivery, "continue", "masked",
                ["该版本已由可信审查遮住该人物，其余许可仍有效"],
                revealed, review,
            )
        if delivery.use not in uses:
            return self._judgement(
                delivery, "continue", "other_use",
                [f"撤回仅涉及 {sorted(uses)}，该交付用途为 {delivery.use}"],
                revealed, review,
            )
        if delivery.state is DeliveryState.RECALLED:
            return self._judgement(
                delivery, "continue", "done", ["已收回，无需再分发"], revealed, review
            )
        direct = self._direct_permission(
            person, delivery.use, delivery.channel, delivery.version, at,
            edit=delivery.edit,
        )
        if direct:
            return self._judgement(
                delivery, "continue", "direct_license",
                [f"该渠道持有授权人单独给出的同用途许可，仅限版本 {delivery.version}"],
                revealed, review, direct=direct,
            )
        if delivery.state is DeliveryState.PENDING:
            return self._judgement(
                delivery, "hold", "not_published", ["尚未发布，暂停新分发"], revealed, review
            )
        reasons = ["授权已撤回，该版本仍露出该人物"]
        if delivery.published_at and delivery.published_at > at:
            reasons.append("撤回生效后仍对外发布")
        if delivery.parent_delivery:
            reasons.append("该副本已交给下游渠道，需按交付编号追收")
            return self._judgement(delivery, "recall", "recall", reasons, revealed, review)
        reasons.append("来源交付，暂停新分发")
        return self._judgement(delivery, "hold", "hold", reasons, revealed, review)

    def _judgement(self, delivery, action, target, reasons, revealed, review, *, direct=None):
        result = {
            "delivery": delivery.id,
            "edit": delivery.edit,
            "version": delivery.version,
            "channel": delivery.channel,
            "use": delivery.use,
            "state": delivery.state.value,
            "parent_delivery": delivery.parent_delivery,
            "chain": delivery_chain(self.store.deliveries, delivery),
            "action": action,
            "target": target,
            "reasons": reasons,
            "visible_segments": [s.as_dict() for s in revealed],
            "review_id": delivery.review_id,
            "review_trusted": bool(review and review.trusted),
            "published_at": _iso(delivery.published_at),
        }
        if direct:
            result["direct_permissions"] = [
                {
                    "version": permission.version,
                    "channel": permission.channel,
                    "use": permission.use,
                    "until": _iso(permission.until),
                }
                for permission in direct
            ]
        return result

    def _responsible(self, person, deliveries) -> dict:
        publishers, received_from = {}, {}
        for judgement in deliveries:
            delivery = self.store.deliveries[judgement["delivery"]]
            publishers.setdefault(delivery.channel, set())
            if delivery.created_by:
                publishers[delivery.channel].add(delivery.created_by)
            received_from.setdefault(delivery.channel, set())
            if delivery.parent_delivery:
                parent = self.store.deliveries.get(delivery.parent_delivery)
                if parent:
                    received_from[delivery.channel].add(parent.channel)
        reviewers = set()
        for review in self.store.reviews.values():
            persons = {p for annotation in review.annotations.values() for p in annotation.persons}
            if review.reviewed_by and person in persons:
                reviewers.add(review.reviewed_by)
        return {
            "publishers": {k: sorted(v) for k, v in publishers.items()},
            "received_from": {k: sorted(v) for k, v in received_from.items()},
            "reviewers": sorted(reviewers),
            "revoked_by": sorted({r.by for r in self.store.revocations.values() if r.by}),
            "note": "人物以演练编号标识，不含身份材料",
        }

    def plan_revocation(
        self, revocation_id, *, operation="hold-distribution", actor=None
    ) -> dict:
        require(actor, "plan_revocation")
        revocation = self.store.revocations.get(revocation_id)
        if revocation is None:
            raise NotFound(f"没有该撤回：{revocation_id}", code="unknown_revocation")
        result = self.impact(revocation.person, use=revocation.use, at=revocation.at)
        created = []
        for judgement in result["deliveries"]:
            if judgement["action"] not in {"recall", "hold"}:
                continue
            request = self._request_for(
                revocation, self.store.deliveries[judgement["delivery"]], operation
            )
            created.append(request.as_dict())
        return {
            "revocation": self._revocation_payload(revocation),
            "impact": {
                "continue": result["continue"],
                "hold": result["hold"],
                "recall": result["recall"],
            },
            "requests": created,
        }

    def _request_for(self, revocation, delivery, operation):
        for request in self.store.requests.values():
            if (
                request.delivery == delivery.id
                and request.revocation == revocation.id
                and request.operation == operation
            ):
                return request
        request = HandlingRequest(
            id=self.store.next_id("req"),
            channel=delivery.channel,
            delivery=delivery.id,
            revocation=revocation.id,
            operation=operation,
            reference=sanitize_identifier(f"rcv-{revocation.id}-{delivery.id}-{operation}"),
            status="planned",
            created_at=self.clock.now(),
        )
        self.store.requests[request.id] = request
        self.store.request_order.append(request.id)
        if delivery.state is DeliveryState.PUBLISHED:
            delivery.state = DeliveryState.HELD
        return request

    def send_request(self, request_id, *, actor=None) -> dict:
        require(actor, "send_correspondence")
        request = self.store.requests.get(request_id)
        if request is None:
            raise NotFound(f"没有该处置请求：{request_id}", code="unknown_request")
        if self.transport is None:
            raise RightsError("未配置对端传输", code="transport_unavailable")
        delivery = self.store.deliveries[request.delivery]
        request.attempts += 1
        try:
            receipt = self.transport.send(
                request.reference, request.operation, request.channel
            )
        except LostReply:
            request.status = "sent_pending_reply"
            request.detail = "回执未送达，可用同一编号重试"
            if delivery.state is DeliveryState.PUBLISHED:
                delivery.state = DeliveryState.HELD
            return request.as_dict()
        request.receipt = receipt
        down = receipt.get("down")
        if down is True:
            request.status = "acknowledged"
            delivery.state = DeliveryState.RECALLED
            self._close_violations_for(delivery.id)
        elif down is False and receipt.get("received"):
            request.status = "acknowledged_still_displayed"
            delivery.state = DeliveryState.STILL_DISPLAYED
            request.detail = "对端称已收到处置请求但仍未下线"
            self._add_violation(
                "still_displayed", delivery.id, delivery.channel,
                request.detail, self.clock.now(),
            )
        else:
            request.status = "acknowledged"
            delivery.state = DeliveryState.HELD
        return request.as_dict()

    def send_all(self, *, actor=None) -> list[dict]:
        return [
            self.send_request(request_id, actor=actor)
            for request_id in list(self.store.request_order)
            if self.store.requests[request_id].status in {"planned", "sent_pending_reply"}
        ]

    def list_requests(self, *, channel=None, actor=None) -> list[dict]:
        if actor is not None and actor.is_channel:
            channel = actor.channel
        return [
            request.as_dict()
            for request in self.store.requests.values()
            if channel is None or request.channel == channel
        ]

    def confirm_revocation(self, revocation_id, *, channel=None, actor=None) -> dict:
        """县级账号确认撤回，并沿交付链追到实际转载端。"""
        require(actor, "confirm_revocation")
        revocation = self.store.revocations.get(revocation_id)
        if revocation is None:
            raise NotFound(f"没有该撤回：{revocation_id}", code="unknown_revocation")
        seed_requests = [
            request
            for request in self.store.requests.values()
            if request.revocation == revocation_id
            and (channel is None or request.channel == channel)
        ]
        seeds = []
        if seed_requests:
            seeds = [self.store.deliveries[r.delivery] for r in seed_requests]
        else:
            # 尚未生成处置请求时，直接从影响面取需要暂停或追收的交付作起点。
            assessment = self.impact(revocation.person, use=revocation.use, at=revocation.at)
            wanted = set(assessment["hold"]) | set(assessment["recall"])
            seeds = [
                self.store.deliveries[did]
                for did in self.store.delivery_order
                if did in wanted and (channel is None or self.store.deliveries[did].channel == channel)
            ]
        traced, seen = [], set()
        for delivery in sorted(seeds, key=lambda d: (d.channel, d.id)):
            for child in [delivery, *descendants(self.store.deliveries, delivery.id)]:
                if child.id in seen:
                    continue
                seen.add(child.id)
                entry = {
                    "delivery": child.id,
                    "channel": child.channel,
                    "parent_delivery": child.parent_delivery,
                    "chain": delivery_chain(self.store.deliveries, child),
                    "state": child.state.value,
                    "authorized_scope": child.authorized_scope,
                }
                existing = next(
                    (
                        r for r in self.store.requests.values()
                        if r.delivery == child.id and r.revocation == revocation_id
                    ),
                    None,
                )
                if existing is None and child.state is not DeliveryState.RECALLED:
                    sub = self._request_for(
                        revocation, child,
                        seed_requests[0].operation if seed_requests else "hold-distribution",
                    )
                    entry["request"] = sub.as_dict()
                elif existing is not None:
                    entry["request"] = existing.as_dict()
                traced.append(entry)
        return {
            "revocation": self._revocation_payload(revocation),
            "confirmed_by": None if actor is None else actor.name,
            "channel": channel,
            "traced": traced,
            "requests": self.list_requests(),
        }

    # ------------------------------------------------------------- 转载回报

    def report_parcel(
        self, delivery_id, channel, *, copies_withdrawn, still_displayed=(),
        independent_license=None, at=None, actor=None,
    ) -> dict:
        """转载端申报：已收回副本、仍展示的版本、独立许可分别核对。"""
        require(actor, "report_parcel")
        require_channel(actor, channel)
        delivery = self._delivery(delivery_id)
        if delivery.channel != channel:
            raise Forbidden("只能申报交给本渠道的交付", details={"delivery": delivery_id})
        moment = to_datetime(at, self.clock.now())
        displayed = tuple(str(v) for v in still_displayed or ())
        delivery.copies_withdrawn = bool(copies_withdrawn)
        delivery.still_displayed = displayed
        delivery.reports.append(
            {
                "at": _iso(moment),
                "copies_withdrawn": bool(copies_withdrawn),
                "still_displayed": list(displayed),
                "independent_license": independent_license,
                "by": None if actor is None else actor.name,
            }
        )
        findings = []
        display_findings = [
            self._finding_display(delivery, item, moment, independent_license)
            for item in displayed
        ]
        findings.append(
            self._finding_copies(delivery, bool(copies_withdrawn), display_findings)
        )
        findings.extend(display_findings)
        if independent_license:
            findings.append(self._verify_license(delivery, independent_license, moment))
        unresolved = [f for f in findings if f.get("action") == "recall"]
        if copies_withdrawn and not displayed and not unresolved:
            delivery.state = DeliveryState.RECALLED
            self._close_violations_for(delivery.id)
        elif displayed:
            delivery.state = DeliveryState.STILL_DISPLAYED
        if unresolved:
            self._add_violation(
                "still_displayed", delivery.id, channel,
                "申报仍展示且无有效许可的版本："
                + ",".join(str(f.get("version") or "?") for f in unresolved),
                moment,
            )
        return {
            "delivery": delivery.id,
            "channel": channel,
            "at": _iso(moment),
            "state": delivery.state.value,
            "findings": findings,
            "needs_recall": bool(unresolved),
        }

    @staticmethod
    def _finding_copies(delivery, copies_withdrawn, display_findings):
        displayed = [f["version"] for f in display_findings]
        if not copies_withdrawn:
            return {
                "item": "copies_withdrawn",
                "claimed": False,
                "verified": False,
                "action": "recall",
                "detail": "申报未收回副本，需继续追收",
            }
        unlicensed = [f["version"] for f in display_findings if f["action"] == "recall"]
        if unlicensed:
            return {
                "item": "copies_withdrawn",
                "claimed": True,
                "verified": False,
                "action": "recall",
                "detail": "仍有未获许可的版本在展示：" + ",".join(unlicensed),
            }
        if displayed:
            return {
                "item": "copies_withdrawn",
                "claimed": True,
                "verified": True,
                "action": "none",
                "detail": "已收回的副本核对通过；仍展示的版本有独立许可："
                + ",".join(displayed),
            }
        return {
            "item": "copies_withdrawn",
            "claimed": True,
            "verified": True,
            "action": "none",
            "detail": "申报收回且无仍展示版本",
        }

    def _finding_display(self, delivery, version, moment, independent_license):
        edit = self._book().edits.get(delivery.edit)
        in_delivery = bool(edit and version in edit.versions)
        versions = [
            candidate
            for candidate_edit in self._book().edits.values()
            for candidate in candidate_edit.versions.values()
            if candidate.id == version
        ]
        license_valid = False
        license_note = None
        if independent_license:
            checked = self._verify_license(delivery, independent_license, moment)
            if checked.get("valid") and checked.get("version") == version:
                license_valid = True
                license_note = checked.get("detail")
        if not license_valid and versions:
            persons = sorted(self._persons_in_version(versions[0]))
            license_valid = any(
                self._direct_permission(
                    person, delivery.use, delivery.channel, version, moment,
                    edit=delivery.edit,
                )
                for person in persons
            )
        if not versions:
            return {
                "item": "still_displayed",
                "version": version,
                "known_version": False,
                "independent_license_valid": False,
                "action": "recall",
                "detail": "申报的版本不存在，需核对实际去向",
            }
        if license_valid:
            return {
                "item": "still_displayed",
                "version": version,
                "known_version": in_delivery,
                "independent_license_valid": True,
                "action": "none",
                "detail": license_note or "该版本有独立许可，可继续展示留用",
            }
        return {
            "item": "still_displayed",
            "version": version,
            "known_version": in_delivery,
            "independent_license_valid": False,
            "action": "recall",
            "detail": "无独立许可，需收回该版本"
            if in_delivery
            else "申报的版本不属于本交付的成品且无独立许可，需核对并收回",
        }

    def record_receipt(self, reference, *, actor=None) -> dict:
        """回执未达时，按编号取回对端已记录的回执。"""
        require(actor, "record_receipt")
        if self.transport is None:
            raise RightsError("未配置对端传输", code="transport_unavailable")
        request = next(
            (r for r in self.store.requests.values() if r.reference == reference), None
        )
        try:
            receipt = self.transport.lookup(reference)
        except LostReply as error:
            raise RightsError(
                "对端仍不可达，请稍后重试", code="transport_unavailable"
            ) from error
        if receipt is None:
            raise NotFound(f"对端没有该编号的回执：{reference}", code="unknown_receipt")
        if request is None:
            return {"reference": reference, "receipt": receipt}
        request.receipt = receipt
        delivery = self.store.deliveries[request.delivery]
        down = receipt.get("down")
        if down is True:
            request.status = "acknowledged"
            delivery.state = DeliveryState.RECALLED
            self._close_violations_for(delivery.id)
        elif down is False and receipt.get("received"):
            request.status = "acknowledged_still_displayed"
            delivery.state = DeliveryState.STILL_DISPLAYED
            request.detail = "对端称已收到处置请求但仍未下线"
        else:
            request.status = "acknowledged"
        return {"reference": reference, "receipt": receipt, "request": request.as_dict()}

    def _verify_license(self, delivery, license_data, at):
        try:
            person = str(license_data["person"])
            channel = str(license_data.get("channel") or delivery.channel)
            version = str(license_data["version"])
            use = str(license_data.get("use") or delivery.use)
        except (KeyError, TypeError):
            return {"item": "independent_license", "valid": False, "action": "recall",
                    "detail": "独立许可要素不全"}
        base = {"item": "independent_license", "person": person, "channel": channel,
                "version": version, "use": use}
        if channel != delivery.channel:
            return {**base, "valid": False, "action": "recall",
                    "detail": "独立许可渠道与申报渠道不一致"}
        known = any(
            candidate.id == version
            for edit in self._book().edits.values()
            for candidate in edit.versions.values()
        )
        if not known:
            return {**base, "valid": False, "action": "recall", "detail": "独立许可版本不存在"}
        matches = self._direct_permission(person, use, channel, version, at, edit=delivery.edit)
        if not matches:
            return {**base, "valid": False, "action": "recall",
                    "detail": "未查到覆盖该渠道、版本与用途的独立许可"}
        permission = matches[0]
        return {**base, "valid": True, "action": "none", "until": _iso(permission.until),
                "detail": "独立许可有效，限该版本与该用途"}

    def record_forward(
        self, origin_delivery, destination, *, detail=None, at=None, actor=None
    ) -> dict:
        """登记未按约定再转递的副本去向，便于追收。"""
        require(actor, "record_forward")
        origin = self._delivery(origin_delivery)
        moment = to_datetime(at, self.clock.now())
        existing = next(
            (
                delivery.id for delivery in self.store.deliveries.values()
                if delivery.channel == destination
                and origin.id in delivery_chain(self.store.deliveries, delivery)
                and delivery.id != origin.id
            ),
            None,
        )
        copy = self._add_unauthorized_copy(
            origin.id, str(destination), detail or "未按许可再转递", moment,
            related=existing, with_violation=True,
        )
        return copy.as_dict()
        return copy.as_dict()

    # ----------------------------------------------------------------- 违规

    def _add_violation(self, kind, delivery, destination, detail, at, *, related=None):
        violation = Violation(
            id=self.store.next_id("vio"), kind=kind, delivery=delivery,
            destination=destination, detail=detail, at=at, related=related,
        )
        self.store.violations[violation.id] = violation
        self.store.violation_order.append(violation.id)
        return violation

    def _add_unauthorized_copy(
        self, origin_delivery, destination, detail, at, *, related=None,
        with_violation=False,
    ):
        for copy in self.store.unauthorized.values():
            if (copy.origin_delivery == origin_delivery
                    and copy.destination == destination and copy.at == at):
                return copy
        copy = UnauthorizedCopy(
            id=self.store.next_id("copy"), origin_delivery=origin_delivery,
            destination=destination, detail=detail, at=at, status="to_recall",
        )
        self.store.unauthorized[copy.id] = copy
        self.store.unauthorized_order.append(copy.id)
        if with_violation:
            self._add_violation(
                "unauthorized_copy", origin_delivery, destination, detail, at,
                related=related,
            )
        return copy

    def _close_violations_for(self, delivery_id):
        for violation in self.store.violations.values():
            if violation.delivery == delivery_id:
                violation.status = "closed"

    def list_violations(self, *, actor=None) -> list[dict]:
        violations = [v.as_dict() for v in self.store.violations.values()]
        if actor is None:
            return violations
        if actor.is_channel:
            return [v for v in violations if v["destination"] == actor.channel]
        require(actor, "read_internal")
        return violations

    def list_unauthorized_copies(self, *, actor=None) -> list[dict]:
        copies = [c.as_dict() for c in self.store.unauthorized.values()]
        if actor is None:
            return copies
        if actor.is_channel:
            return [c for c in copies if c["destination"] == actor.channel]
        require(actor, "read_internal")
        return copies

    # --------------------------------------------------------------- 事件游标

    def ingest_event(self, record: dict) -> dict:
        cursor = record.get("cursor")
        payload = record.get("payload") or {}
        if not isinstance(payload, dict):
            raise ValidationError("消息 payload 应为对象")
        key = str(cursor) if cursor is not None else hashlib.sha256(
            json.dumps(record, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        fingerprint = hashlib.sha256(
            json.dumps(record, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        if key in self.store.seen_events:
            if self.store.seen_events[key]["fingerprint"] != fingerprint:
                raise Conflict(f"事件 {cursor} 内容不一致", code="event_cursor_reused")
            return self.store.seen_events[key]["result"]
        result = self._dispatch_event(record.get("source"), payload, record)
        self.store.seen_events[key] = {"fingerprint": fingerprint, "result": result}
        return result

    def ingest_events(self, records: Iterable[dict]) -> list[dict]:
        return [self.ingest_event(record) for record in records]

    def _dispatch_event(self, source, payload, record) -> dict:
        minute = record.get("minute")
        if source == "publication":
            delivery = self.record_publication(
                payload, event_minute=minute, cursor=record.get("cursor")
            )
            return {"type": "publication", "delivery": delivery}
        if source == "rights":
            revocation = self.revoke(
                authorization=payload.get("authorization"),
                person=payload.get("person"),
                use=payload.get("revoke") or payload.get("use"),
                at=self._event_time(payload, minute, record),
                actor=Actor(Role.RIGHTS, "fixture"),
                by=payload.get("by"),
            )
            return {"type": "revocation", "revocation": revocation}
        if source == "editing":
            version = self.create_version(
                payload["edit"],
                kind=payload.get("kind") or "video",
                uses=payload.get("uses") or self._inherit_uses(payload),
                spans=payload.get("spans") or self._inherit_spans(payload),
                version=payload.get("version"),
                derived_from=payload.get("derived_from"),
                actor=Actor(Role.EDITOR, payload.get("by") or "fixture"),
            )
            return {"type": "version", "version": version}
        if source == "review":
            return self._dispatch_review(payload)
        return {"type": "ignored", "source": source}

    def _event_time(self, payload, minute, record):
        return message_time(payload, minute, self._book().activity_day, self.clock.now())

    def _inherit_uses(self, payload):
        edit = self._book().edits.get(payload["edit"])
        return sorted(edit.uses) if edit else []

    def _inherit_spans(self, payload):
        edit = self._book().edits.get(payload["edit"])
        version = edit.version(payload.get("derived_from")) if edit else None
        if version is None and edit is not None:
            version = edit.version()
        if version is None:
            raise ValidationError("换版本消息缺少可继承的原片区间")
        return [span.as_list() for span in version.spans]

    def _dispatch_review(self, payload):
        action = payload.get("action")
        if action == "submit":
            return {
                "type": "review",
                "review": self.submit_review(
                    payload["edit"], version=payload.get("version"),
                    scope=payload.get("scope"),
                    actor=Actor(Role.EDITOR, payload.get("by") or "fixture"),
                ),
            }
        if action == "approve":
            return {
                "type": "review",
                "review": self.approve_review(
                    payload["review"], actor=Actor(Role.REVIEWER, payload.get("by") or "fixture"),
                ),
            }
        return {"type": "ignored", "source": "review"}

    # -------------------------------------------------------------- 对外快照

    def snapshot(self, *, include_private=False) -> dict:
        """可重复构造的状态快照，便于联调回放与对账。"""
        result = {
            "activity_day": _iso(self._book().activity_day),
            "versions": [
                self._version_payload(version)
                for edit in self._book().edits.values()
                for version in edit.versions.values()
            ],
            "reviews": [self._review_payload(r) for r in self.store.reviews.values()],
            "deliveries": [
                self._delivery_payload(self.store.deliveries[did])
                for did in self.store.delivery_order
            ],
            "revocations": [
                self._revocation_payload(self.store.revocations[rid])
                for rid in self.store.revocation_order
            ],
            "requests": [r.as_dict() for r in self.store.requests.values()],
            "violations": self.list_violations(),
            "unauthorized_copies": self.list_unauthorized_copies(),
        }
        if include_private:
            result["authorizations"] = [
                {
                    "authorization": authorization.id,
                    "person": authorization.person,
                    "uses": sorted(authorization.uses),
                    "until": _iso(authorization.until),
                }
                for authorization in self._book().authorizations.values()
            ]
        return result
