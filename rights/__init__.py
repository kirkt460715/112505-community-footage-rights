"""人员授权、镜头审查与跨渠道撤回的业务后端。

本包只依赖标准库，对外暴露 :class:`RightsService`。命令行入口见
``python3 -m rights``。
"""

from .clock import Clock, FixedClock, SystemClock
from .errors import (
    Conflict,
    Forbidden,
    NotFound,
    RightsError,
    ValidationError,
)
from .model import DeliveryState, ReviewState, Role
from .service import RightsService

__all__ = [
    "Clock",
    "Conflict",
    "DeliveryState",
    "FixedClock",
    "Forbidden",
    "NotFound",
    "ReviewState",
    "RightsError",
    "RightsService",
    "Role",
    "SystemClock",
    "ValidationError",
]
