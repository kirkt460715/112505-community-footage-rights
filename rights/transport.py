"""合作方回执传输。

服务层只依赖 :class:`ReceiptTransport`。演练默认使用
:class:`InMemoryReceiptTransport`（与 ``fixture_gateway.py`` 语义一致），
也可以在联调时换成 :class:`GatewayReceiptTransport`：

* 同一 ``reference`` 与同一 ``(operation, recipient)`` 可重复提交并返回同一回执；
* 同一 ``reference`` 换用途或换接收方返回冲突；
* ``lost_reply`` 首次调用已记录回执但连接断开，用同一编号重试即可取回。
"""

from __future__ import annotations

import json
from threading import Lock
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .errors import Conflict, RightsError, ValidationError


class LostReply(Exception):
    """对端已记录，但回执未送达。应使用同一编号重试。"""


class ReceiptTransport(Protocol):
    def send(self, reference: str, operation: str, recipient: str) -> dict:
        ...

    def lookup(self, reference: str) -> dict | None:
        ...


class InMemoryReceiptTransport:
    """按 ``fixtures/receipts.json`` 示例实现的本地对端。"""

    def __init__(self, examples):
        self._replies = {}
        for entry in examples:
            signature = (entry["operation"], entry["recipient"])
            if signature in self._replies:
                raise ValidationError(f"回执条目重复：{signature}")
            if entry["delivery"] not in {"applied", "lost_reply"}:
                raise ValidationError(f"传输结果无效：{entry['delivery']}")
            self._replies[signature] = entry
        self._requests: dict[str, tuple] = {}
        self._lock = Lock()

    def send(self, reference, operation, recipient):
        signature = (operation, recipient)
        with self._lock:
            previous = self._requests.get(reference)
            if previous is not None:
                if previous[0] != signature:
                    raise Conflict("编号已被另一个操作使用", code="reference_reused")
                # 同号同内容重试：取回已记录的回执，不再断开。
                return dict(previous[1])
            example = self._replies.get(signature)
            if example is None:
                raise RightsError(
                    "没有该操作与接收方的回执示例",
                    code="no_counterparty_example",
                    details={"operation": operation, "recipient": recipient},
                )
            receipt = dict(example["receipt"])
            self._requests[reference] = (signature, receipt)
            if example["delivery"] == "lost_reply":
                raise LostReply(reference)
            return dict(receipt)

    def lookup(self, reference):
        with self._lock:
            entry = self._requests.get(reference)
        return None if entry is None else dict(entry[1])


class GatewayReceiptTransport:
    """连接 ``fixture_gateway.py`` 的 HTTP 传输。"""

    def __init__(self, base_url="http://127.0.0.1:8765", timeout=5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def send(self, reference, operation, recipient):
        body = json.dumps(
            {"reference": reference, "operation": operation, "recipient": recipient}
        ).encode("utf-8")
        request = Request(
            self.base_url + "/v1/receipts",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())["receipt"]
        except HTTPError as error:
            try:
                payload = json.loads(error.read())
            except Exception:  # noqa: BLE001 - 回执体不是 JSON 时保底
                payload = {}
            raise RightsError(
                payload.get("message") or "对端拒绝回执",
                code=payload.get("code") or "receipt_rejected",
                details={"status": error.code},
            ) from error
        except (URLError, ConnectionError, TimeoutError) as error:
            raise LostReply(str(error)) from error

    def lookup(self, reference):
        request = Request(self.base_url + "/v1/receipts/" + reference)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())["receipt"]
        except HTTPError as error:
            if error.code == 404:
                return None
            raise RightsError("回执查询失败", code="receipt_lookup_failed") from error
        except (URLError, ConnectionError, TimeoutError) as error:
            raise LostReply(str(error)) from error
