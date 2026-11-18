import copy
import json
import tempfile
import unittest
from pathlib import Path

from realoria_cc.config import INTERNAL, PUBLIC, RESTRICTED, Settings
from realoria_cc.core import NotFound
from realoria_cc.org import OrgRegistry, RegistryError
from realoria_cc.security import AuthError, Forbidden, authorize, egress_allowed

from .helpers import PW, SystemCase


class OrgRegistryTests(unittest.TestCase):
    def setUp(self):
        self.reg = OrgRegistry.load()

    def test_33_functions_in_6_hqs(self):
        self.assertEqual(len(self.reg.raw["functions"]), 33)
        self.assertEqual(len(self.reg.raw["headquarters"]), 6)
        ranges = {h["id"]: tuple(h["range"]) for h in self.reg.raw["headquarters"]}
        self.assertEqual(ranges, {"HQ1": (1, 6), "HQ2": (7, 14), "HQ3": (15, 20),
                                  "HQ4": (21, 25), "HQ5": (26, 30), "HQ6": (31, 33)})

    def test_future_business_signal_only(self):
        for fid in ("23", "24", "25"):
            self.assertTrue(self.reg.allowed_output(fid, "signal"))
            self.assertFalse(self.reg.allowed_output(fid, "analysis"))
        self.assertTrue(self.reg.allowed_output("22", "analysis"))

    def test_unverified_registry_disables_approvals(self):
        self.assertFalse(self.reg.verified)
        self.assertFalse(self.reg.approvals_enabled)
        self.assertTrue(all(f["approval_authority"] is None for f in self.reg.raw["functions"]))

    def _write(self, raw) -> Path:
        p = Path(tempfile.mkdtemp()) / "reg.json"
        p.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        return p

    def test_rejects_missing_function(self):
        raw = copy.deepcopy(self.reg.raw)
        raw["functions"].pop(10)
        with self.assertRaises(RegistryError):
            OrgRegistry.load(self._write(raw))

    def test_rejects_signal_only_violation(self):
        raw = copy.deepcopy(self.reg.raw)
        raw["functions"][23]["allowed_outputs"] = ["analysis", "signal"]  # 24番
        with self.assertRaises(RegistryError):
            OrgRegistry.load(self._write(raw))

    def test_rejects_authority_on_unverified_function(self):
        raw = copy.deepcopy(self.reg.raw)
        raw["functions"][0]["approval_authority"] = "推測した承認者"
        with self.assertRaises(RegistryError):
            OrgRegistry.load(self._write(raw))


class EgressPolicyTests(unittest.TestCase):
    def test_defaults_block_external(self):
        s = Settings(data_dir=Path("."))
        self.assertFalse(egress_allowed("external", PUBLIC, s)[0])
        self.assertTrue(egress_allowed("mock", RESTRICTED, s)[0])
        self.assertTrue(egress_allowed("local", RESTRICTED, s)[0])

    def test_restricted_never_external_even_if_enabled(self):
        s = Settings(data_dir=Path("."), external_ai_enabled=True,
                     max_external_classification=RESTRICTED)
        self.assertFalse(egress_allowed("external", RESTRICTED, s)[0])
        self.assertTrue(egress_allowed("external", INTERNAL, s)[0])


class AuthTests(SystemCase):
    def test_wrong_password_rejected_and_audited(self):
        with self.assertRaises(AuthError):
            self.system.login("viewer", "wrong-password-123")
        actions = [r["action"] for r in self.system.read_audit(self.admin)]
        self.assertIn("auth.login_failed", actions)

    def test_lockout_after_5_failures(self):
        for _ in range(5):
            with self.assertRaises(AuthError):
                self.system.login("viewer", "wrong-password-123")
        with self.assertRaises(AuthError):
            self.system.login("viewer", PW)  # 正しくてもロック中
        self.clock.advance(901)
        self.system.login("viewer", PW)

    def test_ai_principal_cannot_login(self):
        with self.assertRaises(AuthError):
            self.system.login("agent07", PW)

    def test_session_expiry_and_logout(self):
        tok = self.system.login("viewer", PW)
        self.system.authenticate(tok)
        self.system.logout(tok)
        with self.assertRaises(AuthError):
            self.system.authenticate(tok)
        tok = self.system.login("viewer", PW)
        self.clock.advance(self.settings.session_ttl_seconds + 1)
        with self.assertRaises(AuthError):
            self.system.authenticate(tok)

    def test_unauthenticated_rejected(self):
        with self.assertRaises(AuthError):
            authorize(None, "job.read")
        with self.assertRaises(AuthError):
            self.system.authenticate("forged-token")

    def test_role_separation(self):
        with self.assertRaises(Forbidden):
            self.system.submit_job(self.viewer, function_id="07", instruction="x")
        with self.assertRaises(Forbidden):
            self.system.read_audit(self.op)
        with self.assertRaises(Forbidden):
            self.system.resume_system(self.op, "x")

    def test_ai_cannot_receive_human_roles(self):
        with self.assertRaises(ValueError):
            self.system.create_principal(self.admin, "badai", "ai", "x", {"admin"}, 1)
        with self.assertRaises(ValueError):
            self.system.create_principal(self.admin, "badai", "ai", "x", {"approver"}, 1)

    def test_human_only_actions_reject_ai_even_with_role(self):
        # DB を直接改変して AI に approver を付けても、HUMAN_ONLY で拒否されること
        with self.system.store.tx() as c:
            c.execute("UPDATE principals SET roles='[\"approver\",\"agent\"]' WHERE id='agent07'")
        ai = self.system.get_principal("agent07")
        with self.assertRaises(Forbidden):
            authorize(ai, "approval.decide")

    def test_bootstrap_only_once(self):
        with self.assertRaises(Forbidden):
            self.system.create_principal(None, "evil", "human", "x", {"admin"}, 3, PW,
                                         bootstrap=True)

    def test_approval_disabled_while_unverified(self):
        self.system.create_principal(self.admin, "appr", "human", "承認者", {"approver"}, 1, PW)
        appr = self.system.authenticate(self.system.login("appr", PW))
        with self.assertRaises(Forbidden) as cm:
            self.system.decide_approval(appr, "0" * 32, "approve")
        self.assertIn("未照合", str(cm.exception))

    def test_official_source_registration_disabled(self):
        with self.assertRaises(Forbidden):
            self.system.register_source(self.admin, "s1", "正式", "1", "official", PUBLIC, "x")


class ClassificationTests(SystemCase):
    def setUp(self):
        super().setUp()
        self.system.register_source(self.admin, "raw", "未公開取材", "1", "reference",
                                    RESTRICTED, "未公開素材。")
        self.system.register_source(self.admin, "pub", "公開記事", "1", "reference",
                                    PUBLIC, "公開済み。")

    def test_job_classification_raised_by_sources(self):
        j = self.system.submit_job(self.admin, function_id="07", instruction="x",
                                   source_ids=["raw"], classification=PUBLIC)
        self.assertEqual(j["classification"], RESTRICTED)

    def test_low_clearance_cannot_use_restricted_source(self):
        with self.assertRaises(Forbidden):
            self.system.submit_job(self.op, function_id="07", instruction="x", source_ids=["raw"])

    def test_low_clearance_cannot_see_restricted_jobs_or_sources(self):
        j = self.system.submit_job(self.admin, function_id="07", instruction="x",
                                   source_ids=["raw"])
        self.assertNotIn(j["id"], [x["id"] for x in self.system.list_jobs(self.viewer)])
        with self.assertRaises(Forbidden):
            self.system.get_job(self.viewer, j["id"])
        self.assertEqual([s["id"] for s in self.system.list_sources(self.viewer)], ["pub"])

    def test_unknown_source_rejected(self):
        with self.assertRaises(NotFound):
            self.system.submit_job(self.admin, function_id="07", instruction="x",
                                   source_ids=["nope"])

    def test_signal_only_function_rejects_analysis(self):
        with self.assertRaises(Forbidden):
            self.system.submit_job(self.admin, function_id="24", instruction="x",
                                   output_kind="analysis")
        self.system.submit_job(self.admin, function_id="24", instruction="x",
                               output_kind="signal")


if __name__ == "__main__":
    unittest.main()
