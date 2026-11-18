import json
import threading
import unittest
import urllib.error
import urllib.request

from realoria_cc import agents
from realoria_cc.api import make_server
from realoria_cc.config import INTERNAL, PUBLIC, RESTRICTED
from realoria_cc.providers import EgressDenied, ModelRouter, ProviderUnavailable
from realoria_cc.service import Worker

from .helpers import PW, SystemCase


class AgentTests(SystemCase):
    def setUp(self):
        super().setUp()
        self.system.register_source(self.admin, "pol", "編集方針", "1", "reference", PUBLIC,
                                    "本人確認済みの発言のみ掲載する。事実確認を二重に行う。")
        self.system.register_source(self.admin, "raw", "未公開取材", "1", "reference",
                                    RESTRICTED, "未公開素材。")

    def run_job(self, **kw):
        kw.setdefault("function_id", "07")
        j = self.system.submit_job(self.admin, **kw)
        Worker(self.system, "t").run_once()
        return self.system.get_job(self.admin, j["id"])

    def test_grounded_output_is_draft(self):
        job = self.run_job(instruction="方針を要約", source_ids=["pol"])
        self.assertEqual(job["state"], "succeeded")
        p = job["proposals"][0]
        self.assertEqual(p["status"], "draft")
        self.assertTrue(p["grounding"]["passed"])
        self.assertEqual(p["content"]["findings"][0]["source_ids"], ["pol"])
        self.assertEqual(len(job["model_calls"]), 1)
        self.assertEqual(job["model_calls"][0]["locality"], "mock")

    def test_fabricated_claims_flagged_for_review(self):
        job = self.run_job(instruction="分析 [[fabricate]]", source_ids=["pol"])
        p = job["proposals"][0]
        self.assertEqual(p["status"], "needs_review")
        problems = {i["problem"] for i in p["grounding"]["issues"]}
        self.assertEqual(problems, {"根拠なし", "未提供資料の引用"})

    def test_no_sources_reports_unknown(self):
        job = self.run_job(instruction="根拠なしで分析")
        self.assertIn("確認できません", job["proposals"][0]["content"]["unknowns"][0])

    def test_check_grounding_rejects_non_list(self):
        g = agents.check_grounding({"findings": "text"}, set())
        self.assertFalse(g["passed"])

    def test_external_provider_unavailable_goes_to_hold(self):
        job = self.run_job(instruction="x", source_ids=["pol"], provider="anthropic",
                           model="(未設定)")
        self.assertEqual(job["state"], "held")
        self.assertIn("ProviderUnavailable", job["error"])
        self.assertEqual(job["model_calls"][0]["status"], "unavailable")

    def test_restricted_to_external_denied_even_when_enabled(self):
        self.settings.external_ai_enabled = True
        router = ModelRouter(self.system.store, self.settings, self.system.audit)
        from realoria_cc.providers import PROVIDERS, Provider
        PROVIDERS["fake_ext"] = type("F", (Provider,), {"name": "fake_ext", "label": "F",
                                                        "locality": "external",
                                                        "models": ("m",), "implemented": True})()
        try:
            with self.assertRaises(EgressDenied):
                router.call(provider_name="fake_ext", model="m", system="", prompt="x",
                            classification=RESTRICTED, job_id=None, attempt_id=None, actor="t")
            # 価格未設定は外部区分許可内でも拒否 (費用管理不能)
            self.settings.max_external_classification = INTERNAL
            from realoria_cc.providers import BudgetExceeded
            with self.assertRaises(BudgetExceeded):
                router.call(provider_name="fake_ext", model="m", system="", prompt="x",
                            classification=PUBLIC, job_id=None, attempt_id=None, actor="t")
        finally:
            del PROVIDERS["fake_ext"]
        with self.system.store.read() as c:
            statuses = [r[0] for r in c.execute("SELECT status FROM model_calls")]
        self.assertEqual(statuses, ["egress_denied", "budget_denied"])

    def test_daily_call_limit(self):
        self.settings.daily_call_limit = 1
        self.run_job(instruction="1", source_ids=["pol"])
        job = self.run_job(instruction="2", source_ids=["pol"])
        self.assertEqual(job["state"], "held")
        self.assertIn("BudgetExceeded", job["error"])

    def test_unknown_model_rejected(self):
        router = self.system.router
        with self.assertRaises(ProviderUnavailable):
            router.call(provider_name="mock", model="gpt-x", system="", prompt="",
                        classification=0, job_id=None, attempt_id=None, actor="t")

    def test_prompt_content_not_stored_only_hash(self):
        self.run_job(instruction="秘密の指示文XYZ", source_ids=["pol"])
        with self.system.store.read() as c:
            dump = "\n".join(c.iterdump())
        audit_details = "".join(r["detail"] for r in self.system.read_audit(self.admin))
        self.assertNotIn("秘密の指示文XYZ", audit_details)
        self.assertIn("prompt_sha256", audit_details)
        self.assertIn("秘密の指示文XYZ", dump)  # ジョブ本体には保存される (区分で保護)


class ApiTests(SystemCase):
    def setUp(self):
        super().setUp()
        self.srv = make_server(self.system, "127.0.0.1", 0)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def req(self, method, path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        if body is not None:
            r.add_header("Content-Type", "application/json")
        if token:
            r.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"null"), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null"), e.headers

    def login(self, uid="admin"):
        return self.req("POST", "/api/login", {"id": uid, "password": PW})[1]["token"]

    def test_unauthenticated_requests_rejected(self):
        for m, p in [("GET", "/api/overview"), ("GET", "/api/jobs"), ("POST", "/api/system/stop"),
                     ("GET", "/api/audit")]:
            self.assertEqual(self.req(m, p, {} if m == "POST" else None)[0], 401, p)

    def test_health_is_public_and_minimal(self):
        code, body, _ = self.req("GET", "/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(set(body), {"ok", "code", "halted"})

    def test_security_headers_and_static(self):
        code, _, h = self.req("GET", "/api/health")
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertIn("microphone=()", h["Permissions-Policy"])
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertIn("REALORIA", r.read().decode("utf-8"))

    def test_path_traversal_blocked(self):
        for p in ("/../core.py", "/%2e%2e/core.py", "/ui/../../core.py"):
            self.assertEqual(self.req("GET", p)[0], 404, p)

    def test_full_chat_flow(self):
        tok = self.login()
        code, job, _ = self.req("POST", "/api/jobs", {"function_id": "15",
                                                      "instruction": "読者動向を分析"}, tok)
        self.assertEqual(code, 200, job)
        Worker(self.system, "t").run_once()
        code, detail, _ = self.req("GET", f"/api/jobs/{job['id']}", token=tok)
        self.assertEqual(detail["state"], "succeeded")
        code, ov, _ = self.req("GET", "/api/overview", token=tok)
        self.assertEqual(len(ov["org"]["functions"]), 33)
        self.assertEqual(ov["activity"]["15"]["total"], 1)

    def test_viewer_cannot_submit_or_stop(self):
        tok = self.login("viewer")
        self.assertEqual(self.req("POST", "/api/jobs", {"function_id": "07",
                                                        "instruction": "x"}, tok)[0], 403)
        self.assertEqual(self.req("POST", "/api/system/stop", {}, tok)[0], 403)

    def test_emergency_stop_and_resume_over_api(self):
        op = self.login("op")
        code, st, _ = self.req("POST", "/api/system/stop", {"reason": "訓練"}, op)
        self.assertTrue(st["halted"])
        self.assertEqual(self.req("POST", "/api/jobs", {"function_id": "07",
                                                        "instruction": "x"}, op)[0], 409)
        self.assertEqual(self.req("POST", "/api/system/resume", {}, op)[0], 403)
        code, st, _ = self.req("POST", "/api/system/resume", {"reason": "確認"}, self.login())
        self.assertFalse(st["halted"])

    def test_approval_endpoint_disabled(self):
        self.system.create_principal(self.admin, "appr", "human", "承認者", {"approver"}, 1, PW)
        code, body, _ = self.req("POST", "/api/approvals/" + "a" * 32, {"decision": "approve"},
                                 self.login("appr"))
        self.assertEqual(code, 403)
        self.assertIn("未照合", body["error"])

    def test_rejects_bad_content_type_and_large_body(self):
        tok = self.login()
        r = urllib.request.Request(self.base + "/api/jobs", data=b"x=1", method="POST")
        r.add_header("Authorization", f"Bearer {tok}")
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        self.assertEqual(cm.exception.code, 415)
        big = {"function_id": "07", "instruction": "x" * 300_000}
        self.assertEqual(self.req("POST", "/api/jobs", big, tok)[0], 413)


if __name__ == "__main__":
    unittest.main()
