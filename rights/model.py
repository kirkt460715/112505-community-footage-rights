"""业务枚举与常量。"""

from enum import Enum


class Role(str, Enum):
    EDITOR = "editor"              # 剪辑：提交送审、登记原片与剪辑
    REVIEWER = "reviewer"          # 审片：注明画面人物、确认遮挡范围
    RIGHTS = "rights"              # 授权经办：处理撤回、判断用途
    PUBLICATION = "publication"    # 馆级发布
    COUNTY = "county"              # 县级账号：确认撤回、追转载
    CHANNEL = "channel"            # 合作渠道：只看到交给自己的内容
    PARTNER = "partner"            # 转载端回报
    AUDITOR = "auditor"            # 只读核查


class Use(str, Enum):
    HIGHLIGHTS = "highlights"
    INTERNAL = "internal"
    POSTER = "poster"
    PUBLIC = "public"


INTERNAL_USES = {Use.INTERNAL.value}
"""只用于内部课件、不进入公共渠道的用途。"""


class ReviewState(str, Enum):
    PENDING = "pending"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    RETURNED = "returned"          # 已替换版本，旧记录不可套用


class DeliveryState(str, Enum):
    PENDING = "pending"            # 已登记、尚未对外发布
    PUBLISHED = "published"
    HELD = "held"                  # 暂停新分发
    STILL_DISPLAYED = "still_displayed"  # 对端称已收到但未下线
    RECALLED = "recalled"          # 已收回


METHODS = {"mask", "exclude", "verify_clear"}
"""审片可确认的处置方式：遮挡、剔除该区间、确认无该人物。"""
