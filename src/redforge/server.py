"""HTTP entry point for RedForge."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import ScopeViolationError, Service

SCOPE_PATH = "/v1/scope/evaluate"
MATCH_PATH = "/v1/vulnerabilities/match"
CONSOLIDATE_PATH = "/v1/findings/consolidate"
RETEST_PATH = "/v1/findings/retest"
PLAN_PATH = "/v1/attack-chains/plan"
REPORT_PATH = "/v1/reports/export"
POST_PATHS = (
    SCOPE_PATH,
    MATCH_PATH,
    CONSOLIDATE_PATH,
    RETEST_PATH,
    PLAN_PATH,
    REPORT_PATH,
)
MAX_BODY_BYTES = 1024 * 1024


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

    def send_error_json(self, status: int, code: str, message: str) -> None:
        self.send_json(status, {"error": {"code": code, "message": message}})

    def not_found(self) -> None:
        self.send_error_json(404, "not_found", f"no route for {self.path}")

    def reject_non_post(self) -> None:
        if self.path in POST_PATHS:
            self.send_error_json(405, "method_not_allowed", "use POST for this route")
            return
        self.send_error(501, "Unsupported method (%r)" % self.command)

    def do_GET(self) -> None:
        if self.path in POST_PATHS:
            self.send_error_json(405, "method_not_allowed", "use POST for this route")
            return
        if self.path == "/healthz":
            self.send_json(200, self.service.health())
            return
        self.not_found()

    def do_POST(self) -> None:
        if self.path == SCOPE_PATH:
            self._handle_json_post(self.service.evaluate_scope)
            return
        if self.path == MATCH_PATH:
            self._handle_json_post(self.service.match_vulnerabilities)
            return
        if self.path == CONSOLIDATE_PATH:
            self._handle_json_post(self.service.consolidate_findings)
            return
        if self.path == RETEST_PATH:
            self._handle_json_post(self.service.retest_findings)
            return
        if self.path == PLAN_PATH:
            self._handle_json_post(self.service.plan_attack_chains)
            return
        if self.path == REPORT_PATH:
            self._handle_json_post(self.service.export_report)
            return
        self.not_found()

    def _handle_json_post(self, handler) -> None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isdigit():
            self.send_error_json(
                400, "invalid_request", "missing or invalid Content-Length"
            )
            return
        length = int(raw_length)
        if length > MAX_BODY_BYTES:
            # Do not drain an oversized body; drop the connection instead.
            self.close_connection = True
            self.send_error_json(413, "request_too_large", "body exceeds 1 MiB")
            return
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            self.send_error_json(400, "invalid_request", f"malformed JSON: {exc}")
            return
        try:
            result = handler(payload)
        except ScopeViolationError as exc:
            self.send_error_json(403, "scope_violation", str(exc))
            return
        except ValueError as exc:
            self.send_error_json(400, "invalid_request", str(exc))
            return
        self.send_json(200, result)

    do_PUT = reject_non_post
    do_DELETE = reject_non_post
    do_PATCH = reject_non_post
    do_HEAD = reject_non_post

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
