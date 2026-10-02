"""HTTP entry point for RedForge."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import Service

SCOPE_PATH = "/v1/scope/evaluate"
MAX_BODY_BYTES = 1024 * 1024  # 1 MiB


def env_address() -> tuple[str, int]:
    raw = os.environ.get("REDFORGE_ADDR", "127.0.0.1:8080")
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"invalid REDFORGE_ADDR: {raw!r}")
    return host, int(port)


class Handler(BaseHTTPRequestHandler):
    service = Service()

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self) -> None:
        self.send_json(404, {"error": {"code": "not_found", "message": f"no route for {self.path}"}})

    def _method_not_allowed(self) -> None:
        self.send_json(
            405,
            {"error": {"code": "method_not_allowed", "message": f"method {self.command} not allowed for {self.path}"}},
        )

    def _reject_other_methods(self) -> None:
        if self.path == SCOPE_PATH:
            self._method_not_allowed()
        else:
            self._not_found()

    def do_GET(self) -> None:
        if self.path == SCOPE_PATH:
            self._method_not_allowed()
            return
        if self.path == "/healthz":
            self.send_json(200, self.service.health())
            return
        self._not_found()

    do_PUT = _reject_other_methods
    do_DELETE = _reject_other_methods
    do_PATCH = _reject_other_methods
    do_HEAD = _reject_other_methods
    do_OPTIONS = _reject_other_methods

    def do_POST(self) -> None:
        if self.path != SCOPE_PATH:
            self._not_found()
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length < 0:
            length = 0
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            self.send_json(
                413,
                {"error": {"code": "request_too_large", "message": "request body exceeds 1 MiB"}},
            )
            return
        body = self.rfile.read(length) if length else b""
        if len(body) > MAX_BODY_BYTES:
            self.close_connection = True
            self.send_json(
                413,
                {"error": {"code": "request_too_large", "message": "request body exceeds 1 MiB"}},
            )
            return
        try:
            payload = json.loads(body)
        except ValueError:
            self.send_json(400, {"error": {"code": "invalid_request", "message": "request body is not valid JSON"}})
            return
        try:
            result = self.service.evaluate_scope(payload)
        except ValueError as exc:
            self.send_json(400, {"error": {"code": "invalid_request", "message": str(exc)}})
            return
        self.send_json(200, result)

    def log_message(self, fmt: str, *args: object) -> None:
        """Silence per-request logging so recorded output stays stable."""


def main() -> int:
    parser = argparse.ArgumentParser(prog="redforge.server", description="渗透测试与攻防演练平台")
    host, port = env_address()
    parser.add_argument("--host", default=host)
    parser.add_argument("--port", type=int, default=port)
    args = parser.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"RedForge listening on http://{args.host}:{httpd.server_address[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
