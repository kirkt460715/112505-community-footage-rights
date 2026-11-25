"""命令行入口：``python3 -m rights``。"""

from __future__ import annotations

import argparse
from pathlib import Path

from .clock import FixedClock, SystemClock
from .service import RightsService
from .transport import GatewayReceiptTransport, InMemoryReceiptTransport
from .web import RightsServer


def main(argv=None):
    parser = argparse.ArgumentParser(description="民俗活动影像授权与撤回后端")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).resolve().parent.parent / "fixtures")
    parser.add_argument("--clock", default=None, help="固定时钟起点，例如 2028-10-03T00:00:00")
    parser.add_argument(
        "--gateway", default=None,
        help="改为连接轮询对端回执的地址，例如 http://127.0.0.1:8765",
    )
    options = parser.parse_args(argv)
    service = RightsService.from_fixtures(
        options.fixtures,
        clock=FixedClock(options.clock) if options.clock else SystemClock(),
        transport=GatewayReceiptTransport(options.gateway) if options.gateway else None,
    )
    if options.gateway is None:
        import json

        examples = json.loads(
            (options.fixtures / "receipts.json").read_text(encoding="utf-8")
        )
        service.transport = InMemoryReceiptTransport(examples)
    with RightsServer(options.port, service) as server:
        print(f"授权后端 http://127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
