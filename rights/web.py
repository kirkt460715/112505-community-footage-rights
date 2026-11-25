"""HTTP 适配层：把业务服务暴露成可重复调用的本地接口。

只依赖标准库。用 ``python3 -m rights --port 8766`` 启动。接口按角色裁剪数据：

* ``POST /v1/...`` 的调用方用请求头 ``X-Role`` 与可选的 ``X-Actor``、
  ``X-Channel`` 表示，缺省为只读核查角色。
* 渠道角色只能读取与处置交给自己的交付。
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock
from urllib.parse import parse_qs, urlsplit

from .errors import RightsError, ValidationError
from .security import Actor


def _actor(handler) -> Actor:
    role = handler.headers.get("X-Role") or "auditor"
    return Actor(role, handler.headers.get("X-Actor"), handler.headers.get("X-Channel"))


class RightsApplication:
    """纯函数式路由，便于测试与嵌入其他 WSGI/ASGI 框架。"""

    def __init__(self, service):
        self.service = service
        self.lock = Lock()

    def handle(self, method, path, query, body, actor):
        parts = urlsplit(path)
        segments = [s for s in parts.path.split("/") if s]
        query = query or parse_qs(parts.query)
        with self.lock:
            return self._route(method, segments, query, body, actor)

    def _route(self, method, segments, query, body, actor):
        if not segments or segments[0] != "v1":
            raise ValidationError("未知接口")
        tail = segments[1:]
        if tail == ["registers"] and method == "GET":
            return 200, self.service.snapshot(include_private=False)
        if tail == ["edits"] and method == "GET":
            return 200, {"items": self.service.list_edits()}
        if len(tail) == 3 and tail[0] == "edits" and tail[2] == "brief" and method == "GET":
            version = query.get("version", [None])[0]
            return 200, self.service.editor_brief(tail[1], version, actor=actor)
        if len(tail) == 2 and tail[0] == "edits" and tail[1] == "history" and method == "GET":
            edit = query.get("edit", [None])[0]
            return 200, self.service.edit_history(edit, actor=actor)
        if len(tail) == 3 and tail[0] == "edits" and tail[2] == "versions" and method == "POST":
            return 201, self.service.create_version(tail[1], actor=actor, **_body(body))
        if len(tail) == 3 and tail[0] == "edits" and tail[2] == "reviews" and method == "POST":
            version = _body(body).get("version")
            scope = _body(body).get("scope")
            return 201, self.service.submit_review(
                tail[1], version=version, scope=scope, actor=actor
            )
        if len(tail) == 3 and tail[0] == "edits" and tail[2] == "publications" and method == "POST":
            payload = _body(body)
            result = self.service.publish(
                tail[1],
                payload["channel"],
                version=payload.get("version"),
                use=payload.get("use"),
                delivery=payload.get("delivery"),
                parent_delivery=payload.get("parent_delivery"),
                at=payload.get("at"),
                actor=actor,
            )
            return 201, result
        if tail == ["reviews"] and method == "GET":
            return 200, {
                "items": self.service.list_reviews(
                    edit=query.get("edit", [None])[0],
                    version=query.get("version", [None])[0],
                )
            }
        if len(tail) == 2 and tail[0] == "reviews" and method == "GET":
            return 200, self.service.get_review(tail[1], actor=actor)
        if len(tail) == 3 and tail[0] == "reviews" and tail[2] == "annotations" and method == "POST":
            payload = _body(body)
            return 200, self.service.annotate(
                tail[1], payload["span_index"], payload.get("persons") or (),
                recognized=payload.get("recognized", True),
                note=payload.get("note"), actor=actor,
            )
        if len(tail) == 3 and tail[0] == "reviews" and tail[2] == "masks" and method == "POST":
            payload = _body(body)
            return 200, self.service.add_mask(
                tail[1], payload["person"], payload["span_index"],
                payload["start"], payload["end"],
                method=payload.get("method", "mask"), actor=actor,
            )
        if len(tail) == 3 and tail[0] == "reviews" and tail[2] == "approve" and method == "POST":
            return 200, self.service.approve_review(tail[1], actor=actor)
        if len(tail) == 3 and tail[0] == "reviews" and tail[2] == "reject" and method == "POST":
            return 200, self.service.reject_review(
                tail[1], reason=_body(body).get("reason"), actor=actor
            )
        if tail == ["revocations"] and method == "POST":
            payload = _body(body)
            return 201, self.service.revoke(
                authorization=payload.get("authorization"),
                person=payload.get("person"),
                use=payload.get("use") or payload.get("revoke"),
                at=payload.get("at"),
                by=payload.get("by"),
                actor=actor,
            )
        if tail == ["impact"] and method == "GET":
            return 200, self.service.impact(
                query["person"][0],
                use=query.get("use", [None])[0],
                at=query.get("at", [None])[0],
                actor=actor,
            )
        if len(tail) == 2 and tail[0] == "revocations" and tail[1] == "plan" and method == "POST":
            payload = _body(body)
            return 201, self.service.plan_revocation(
                payload["revocation"], operation=payload.get("operation", "hold-distribution"),
                actor=actor,
            )
        if len(tail) == 3 and tail[0] == "revocations" and tail[2] == "confirm" and method == "POST":
            payload = _body(body)
            return 200, self.service.confirm_revocation(
                tail[1], channel=payload.get("channel"), actor=actor
            )
        if tail == ["requests"] and method == "GET":
            return 200, {"items": self.service.list_requests(actor=actor)}
        if len(tail) == 2 and tail[0] == "requests" and tail[1] == "send" and method == "POST":
            return 200, self.service.send_all(actor=actor)
        if len(tail) == 3 and tail[0] == "receipts" and tail[2] == "record" and method == "POST":
            return 200, self.service.record_receipt(tail[1], actor=actor)
        if len(tail) == 2 and tail[0] == "receipts" and method == "GET":
            return 200, self.service.record_receipt(tail[1], actor=actor)
        if tail == ["channels"] and method == "GET":
            return 200, self.service.channel_view(query["channel"][0], actor=actor)
        if len(tail) == 3 and tail[0] == "channels" and tail[2] == "parcels" and method == "POST":
            payload = _body(body)
            return 201, self.service.report_parcel(
                payload["delivery"], tail[1],
                copies_withdrawn=bool(payload.get("copies_withdrawn")),
                still_displayed=payload.get("still_displayed") or (),
                independent_license=payload.get("independent_license"),
                at=payload.get("at"), actor=actor,
            )
        if tail == ["forwards"] and method == "POST":
            payload = _body(body)
            return 201, self.service.record_forward(
                payload["origin_delivery"], payload["destination"],
                detail=payload.get("detail"), at=payload.get("at"), actor=actor,
            )
        if tail == ["violations"] and method == "GET":
            return 200, {"items": self.service.list_violations(actor=actor)}
        if tail == ["copies"] and method == "GET":
            return 200, {"items": self.service.list_unauthorized_copies(actor=actor)}
        if len(tail) == 2 and tail[0] == "deliveries" and method == "GET":
            return 200, self.service.get_delivery(tail[1], actor=actor)
        if tail == ["events"] and method == "POST":
            return 201, {"results": self.service.ingest_events(_body(body).get("events") or [])}
        raise ValidationError("未知接口", details={"path": "/" + "/".join(segments)})


def _body(body):
    if body is None:
        return {}
    if not isinstance(body, dict):
        raise ValidationError("请求正文应为 JSON 对象")
    return body


class RightsHandler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self, method):
        size = int(self.headers.get("Content-Length", "0") or 0)
        body = None
        if size:
            if size > 1_048_576:
                self._send(413, {"error": "payload_too_large"})
                return
            try:
                body = json.loads(self.rfile.read(size))
            except json.JSONDecodeError:
                self._send(400, {"error": "invalid_json"})
                return
        try:
            status, payload = self.server.application.handle(
                method, self.path, None, body, _actor(self)
            )
        except RightsError as error:
            self._send(error.status, error.as_dict())
            return
        self._send(status, payload)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def log_message(self, *args):
        return


class RightsServer(ThreadingHTTPServer):
    def __init__(self, port, service):
        self.application = RightsApplication(service)
        super().__init__(("127.0.0.1", port), RightsHandler)
