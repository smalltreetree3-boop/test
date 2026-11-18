"""HTTP API + 静的UI配信 (標準ライブラリのみ)。

既定で 127.0.0.1 のみで待ち受ける。認証は Bearer トークン (Cookie 不使用のため CSRF 耐性)。
"""
from __future__ import annotations

import json
import logging
import mimetypes
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .core import Conflict, Halted, NotFound, System
from .providers import PROVIDERS
from .security import AuthError, Forbidden, authorize
from .service import health

log = logging.getLogger("realoria_cc.api")
UI_DIR = Path(__file__).parent / "ui"
MAX_BODY = 256 * 1024

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self';"
                               " script-src 'self'; connect-src 'self'; frame-ancestors 'none';"
                               " base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def make_handler(system: System):
    routes: list[tuple[str, re.Pattern, callable]] = []

    def route(method, pattern):
        def deco(fn):
            routes.append((method, re.compile("^" + pattern + "$"), fn))
            return fn
        return deco

    # ---------------------------------------------------------------- routes
    @route("GET", "/api/health")
    def _health(h, p, m):
        code, body = health(system)
        return {"ok": code == 0, "code": code, "halted": body["halted"]}

    @route("POST", "/api/login")
    def _login(h, p, m):
        b = h.json_body()
        token = system.login(str(b.get("id", "")), str(b.get("password", "")))
        return {"token": token}

    @route("POST", "/api/logout")
    def _logout(h, p, m):
        h.principal()
        system.logout(h.token())
        return {"ok": True}

    @route("GET", "/api/me")
    def _me(h, p, m):
        return h.principal().as_dict()

    @route("GET", "/api/overview")
    def _overview(h, p, m):
        pr = h.principal()
        authorize(pr, "org.read")
        st = system.status()
        jobs = system.list_jobs(pr, limit=200)
        by_fn: dict[str, dict] = {}
        for j in jobs:
            d = by_fn.setdefault(j["function_id"], {"total": 0, "active": 0, "held": 0,
                                                    "last_state": None, "last_at": 0})
            d["total"] += 1
            d["active"] += j["state"] in ("queued", "running")
            d["held"] += j["state"] == "held"
            if j["updated_at"] > d["last_at"]:
                d["last_at"], d["last_state"] = j["updated_at"], j["state"]
        return {"status": st, "org": system.registry.as_dict(), "activity": by_fn,
                "voice_input_enabled": system.settings.voice_input_enabled,
                "recent_jobs": jobs[:15], "providers": [pv.describe(system.settings)
                                                        for pv in PROVIDERS.values()]}

    @route("GET", "/api/providers")
    def _providers(h, p, m):
        h.principal()
        return [pv.describe(system.settings) for pv in PROVIDERS.values()]

    @route("GET", "/api/jobs")
    def _jobs(h, p, m):
        return system.list_jobs(h.principal(), limit=int(p.get("limit", ["50"])[0]))

    @route("POST", "/api/jobs")
    def _submit(h, p, m):
        b = h.json_body()
        return system.submit_job(
            h.principal(), function_id=str(b.get("function_id", "")),
            instruction=str(b.get("instruction", "")),
            source_ids=[str(x) for x in b.get("source_ids", [])],
            classification=int(b.get("classification", 0)),
            provider=str(b.get("provider", "mock")), model=str(b.get("model", "mock-analyst-1")),
            output_kind=str(b.get("output_kind", "analysis")),
            idempotency_key=b.get("idempotency_key"))

    @route("GET", r"/api/jobs/(?P<jid>[0-9a-f]{32})")
    def _job(h, p, m):
        return system.get_job(h.principal(), m["jid"])

    @route("POST", r"/api/jobs/(?P<jid>[0-9a-f]{32})/(?P<op>pause|resume|cancel|release)")
    def _control(h, p, m):
        b = h.json_body(optional=True)
        return system.control_job(h.principal(), m["jid"], m["op"], str(b.get("reason", "")))

    @route("POST", r"/api/jobs/(?P<jid>[0-9a-f]{32})/model")
    def _model(h, p, m):
        b = h.json_body()
        return system.change_model(h.principal(), m["jid"], str(b.get("provider")),
                                   str(b.get("model")))

    @route("POST", "/api/system/stop")
    def _stop(h, p, m):
        b = h.json_body(optional=True)
        system.emergency_stop(h.principal(), str(b.get("reason", "UIからの緊急停止")))
        return system.status()

    @route("POST", "/api/system/resume")
    def _resume(h, p, m):
        b = h.json_body(optional=True)
        system.resume_system(h.principal(), str(b.get("reason", "")))
        return system.status()

    @route("GET", "/api/audit")
    def _audit(h, p, m):
        return system.read_audit(h.principal(), after=int(p.get("after", ["0"])[0]))

    @route("POST", "/api/audit/verify")
    def _verify(h, p, m):
        return system.verify_audit(h.principal()).as_dict()

    @route("GET", "/api/sources")
    def _sources(h, p, m):
        return system.list_sources(h.principal())

    @route("POST", "/api/sources")
    def _register(h, p, m):
        b = h.json_body()
        return system.register_source(h.principal(), str(b["id"]), str(b["title"]),
                                      str(b["version"]), str(b.get("status", "reference")),
                                      int(b.get("classification", 1)), str(b["content"]))

    @route("POST", r"/api/approvals/(?P<pid>[0-9a-f]{32})")
    def _approve(h, p, m):
        b = h.json_body(optional=True)
        system.decide_approval(h.principal(), m["pid"], str(b.get("decision", "")))
        return {"ok": True}

    # --------------------------------------------------------------- handler
    class Handler(BaseHTTPRequestHandler):
        server_version = "realoria-cc"
        sys_version = ""

        def log_message(self, fmt, *args):
            log.info("%s %s", self.address_string(), fmt % args)

        def token(self) -> str | None:
            a = self.headers.get("Authorization", "")
            return a[7:] if a.startswith("Bearer ") else None

        def principal(self):
            return system.authenticate(self.token())

        def json_body(self, optional: bool = False) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ApiError(413, "リクエストが大きすぎます")
            if n == 0:
                if optional:
                    return {}
                raise ApiError(400, "本文がありません")
            if "application/json" not in self.headers.get("Content-Type", ""):
                raise ApiError(415, "application/json で送信してください")
            try:
                b = json.loads(self.rfile.read(n).decode("utf-8"))
            except ValueError:
                raise ApiError(400, "JSONが不正です") from None
            if not isinstance(b, dict):
                raise ApiError(400, "JSONオブジェクトで送信してください")
            return b

        def send(self, status: int, body: bytes, ctype: str):
            self.send_response(status)
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            # 音声入力は既定で無効 (ブラウザの音声認識はクラウドへ音声を送る実装があるため)。
            mic = "(self)" if system.settings.voice_input_enabled else "()"
            self.send_header("Permissions-Policy", f"microphone={mic}, camera=(), geolocation=()")
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status: int, obj):
            self.send(status, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"),
                      "application/json; charset=utf-8")

        def dispatch(self, method: str):
            u = urlparse(self.path)
            if method == "GET" and not u.path.startswith("/api/"):
                return self.static(u.path)
            for meth, pat, fn in routes:
                mt = pat.match(u.path)
                if mt and meth == method:
                    try:
                        return self.send_json(200, fn(self, parse_qs(u.query), mt.groupdict()))
                    except ApiError as e:
                        return self.send_json(e.status, {"error": e.message})
                    except AuthError as e:
                        return self.send_json(401, {"error": str(e)})
                    except Forbidden as e:
                        return self.send_json(403, {"error": str(e)})
                    except NotFound as e:
                        return self.send_json(404, {"error": f"見つかりません: {e}"})
                    except (Conflict, Halted) as e:
                        return self.send_json(409, {"error": str(e)})
                    except (ValueError, KeyError, TypeError) as e:
                        return self.send_json(400, {"error": f"入力が不正です: {e}"})
                    except Exception:
                        log.exception("unhandled")
                        return self.send_json(500, {"error": "内部エラー"})
            return self.send_json(404, {"error": "not found"})

        def static(self, path: str):
            if path in ("", "/"):
                path = "/index.html"
            target = (UI_DIR / path.lstrip("/")).resolve()
            if UI_DIR.resolve() not in target.parents or not target.is_file():
                return self.send_json(404, {"error": "not found"})
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            return self.send(200, target.read_bytes(), ctype)

        def do_GET(self):
            self.dispatch("GET")

        def do_POST(self):
            self.dispatch("POST")

    return Handler


def make_server(system: System, host: str | None = None, port: int | None = None):
    host = host or system.settings.host
    port = system.settings.port if port is None else port
    return ThreadingHTTPServer((host, port), make_handler(system))
