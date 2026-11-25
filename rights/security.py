"""权限与可见范围。

不同角色只应看到办理自己那一段所需的信息：

* 编辑：审片需要的授权范围（人物、用途、时段、区间），不含授权人的身份材料；
* 渠道：只看交给自己的交付与处置请求；
* 审片：只能看被送审版本的画面人物标注，不接触身份材料；
* 授权与县级：看撤回影响与责任人。

这里只做“能不能取到”和“取到后裁剪”，业务判断留在服务层。
"""

from __future__ import annotations

from .errors import Forbidden, ValidationError
from .model import Role


def normalize_role(value) -> Role:
    if isinstance(value, Role):
        return value
    try:
        return Role(str(value))
    except ValueError as error:
        raise ValidationError(f"未知角色：{value}") from error


class Actor:
    def __init__(self, role, name: str | None = None, channel: str | None = None):
        self.role = normalize_role(role)
        self.name = name
        self.channel = channel

    def __repr__(self):
        return f"Actor({self.role.value}, {self.name!r}, {self.channel!r})"

    @property
    def is_channel(self) -> bool:
        return self.role in {Role.CHANNEL, Role.PARTNER}


REQUIRED_ROLE = {
    "read_internal": {Role.EDITOR, Role.REVIEWER, Role.RIGHTS, Role.PUBLICATION,
                      Role.COUNTY, Role.AUDITOR},
    "read_brief": {Role.EDITOR, Role.REVIEWER, Role.RIGHTS, Role.PUBLICATION,
                   Role.COUNTY, Role.AUDITOR},
    "register_source": {Role.EDITOR},
    "create_version": {Role.EDITOR},
    "submit_review": {Role.EDITOR},
    "annotate": {Role.REVIEWER},
    "approve_review": {Role.REVIEWER},
    "reject_review": {Role.REVIEWER},
    "publish": {Role.PUBLICATION, Role.COUNTY},
    "record_publication": {Role.PUBLICATION, Role.COUNTY},
    "revoke": {Role.RIGHTS},
    "plan_revocation": {Role.RIGHTS, Role.PUBLICATION, Role.COUNTY},
    "send_correspondence": {Role.PUBLICATION, Role.COUNTY},
    "record_receipt": {Role.PUBLICATION, Role.COUNTY},
    "grant_scope": {Role.COUNTY},
    "confirm_revocation": {Role.COUNTY},
    "report_parcel": {Role.PARTNER, Role.CHANNEL},
    "record_forward": {Role.COUNTY, Role.PUBLICATION},
    "judge_use": {Role.RIGHTS, Role.PUBLICATION, Role.COUNTY, Role.AUDITOR},
}


def require(actor: Actor | None, action: str) -> Actor:
    if actor is None:
        raise Forbidden("需要经办人身份")
    allowed = REQUIRED_ROLE.get(action)
    if allowed and actor.role not in allowed:
        raise Forbidden(
            f"角色 {actor.role.value} 不能执行 {action}",
            details={"action": action, "role": actor.role.value},
        )
    return actor


def require_channel(actor: Actor, channel: str) -> None:
    """渠道只能对交给自己的内容办事。"""
    if actor.is_channel and actor.channel != channel:
        raise Forbidden(
            "该交付不在本渠道的可见范围内",
            details={"channel": channel},
        )
