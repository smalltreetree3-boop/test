import threading
import unittest

from realoria_cc.core import Conflict, Halted, StaleLease
from realoria_cc.security import Forbidden

from .helpers import SystemCase


class JobLifecycleTests(SystemCase):
    def submit(self, **kw):
        kw.setdefault("function_id", "07")
        kw.setdefault("instruction", "分析")
        return self.system.submit_job(self.admin, **kw)

    def test_idempotent_submit(self):
        a = self.submit(idempotency_key="k1")
        b = self.submit(idempotency_key="k1")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(len(self.system.list_jobs(self.admin)), 1)

    def test_single_claim_under_concurrency(self):
        self.submit()
        results = []
        barrier = threading.Barrier(8)

        def worker(i):
            barrier.wait()
            results.append(self.system.claim(f"w{i}"))
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sum(1 for r in results if r is not None), 1)

    def test_successful_finish(self):
        j = self.submit()
        lease = self.system.claim("w1")
        self.assertEqual(lease.job_id, j["id"])
        self.assertEqual(self.system.finish(lease, ok=True, result={"x": 1}), "succeeded")
        # 二重完了は拒否
        with self.assertRaises(StaleLease):
            self.system.finish(lease, ok=True)

    def test_stale_owner_write_rejected_after_reclaim(self):
        self.submit()
        old = self.system.claim("w1")
        self.clock.advance(31)                  # リース切れ (w1 が停止したと想定)
        self.assertEqual(self.system.reap()["requeued"], [old.job_id])
        new = self.system.claim("w2")
        self.assertGreater(new.token, old.token)
        with self.assertRaises(StaleLease):     # 復帰した旧所有者の書込みは拒否
            self.system.finish(old, ok=True, result={"stale": True})
        with self.assertRaises(StaleLease):
            self.system.heartbeat(old)
        self.assertEqual(self.system.finish(new, ok=True), "succeeded")
        job = self.system.get_job(self.admin, new.job_id)
        self.assertIsNone(job["result"])        # 旧所有者の結果は混入していない

    def test_expired_lease_cannot_write_even_before_reap(self):
        self.submit()
        lease = self.system.claim("w1")
        self.clock.advance(31)
        with self.assertRaises(StaleLease):
            self.system.finish(lease, ok=True)

    def test_heartbeat_extends_lease(self):
        self.submit()
        lease = self.system.claim("w1")
        for _ in range(5):
            self.clock.advance(20)
            self.system.heartbeat(lease)
        self.assertEqual(self.system.reap(), {"requeued": [], "held": []})
        self.assertEqual(self.system.finish(lease, ok=True), "succeeded")

    def test_retry_limit_then_failed(self):
        j = self.submit()
        states = []
        for _ in range(3):
            self.clock.advance(10)
            lease = self.system.claim("w1")
            states.append(self.system.finish(lease, ok=False, error="一時障害"))
        self.assertEqual(states, ["queued", "queued", "failed"])
        self.assertEqual(self.system.get_job(self.admin, j["id"])["attempts"], 3)

    def test_backoff_delays_retry(self):
        self.submit()
        lease = self.system.claim("w1")
        self.system.finish(lease, ok=False, error="一時障害")
        self.assertIsNone(self.system.claim("w1"))   # バックオフ中
        self.clock.advance(1.1)
        self.assertIsNotNone(self.system.claim("w1"))

    def test_orphan_non_retry_safe_goes_to_hold(self):
        j = self.submit(retry_safe=False)
        self.system.claim("w1")
        self.clock.advance(31)
        out = self.system.reap()
        self.assertEqual(out["held"], [j["id"]])
        job = self.system.get_job(self.admin, j["id"])
        self.assertEqual(job["state"], "held")
        self.assertIn("孤立", job["hold_reason"])
        self.assertIsNone(self.system.claim("w2"))   # Hold は自動実行されない

    def test_orphan_after_max_attempts_goes_to_hold(self):
        j = self.submit()
        for _ in range(3):
            self.system.claim("w1")
            self.clock.advance(31)
            self.system.reap()
        self.assertEqual(self.system.get_job(self.admin, j["id"])["state"], "held")

    def test_release_hold_is_human_only_and_allows_one_attempt(self):
        j = self.submit(retry_safe=False)
        self.system.claim("w1")
        self.clock.advance(31)
        self.system.reap()
        with self.assertRaises(Forbidden):
            self.system.control_job(self.viewer, j["id"], "release")
        self.system.control_job(self.op, j["id"], "release", reason="確認済み")
        lease = self.system.claim("w2")
        self.assertEqual(lease.job_id, j["id"])

    def test_pause_resume_cancel_queued(self):
        j = self.submit()
        self.assertEqual(self.system.control_job(self.op, j["id"], "pause")["state"], "paused")
        self.assertIsNone(self.system.claim("w1"))
        self.assertEqual(self.system.control_job(self.op, j["id"], "resume")["state"], "queued")
        self.assertEqual(self.system.control_job(self.op, j["id"], "cancel")["state"], "cancelled")
        with self.assertRaises(Conflict):
            self.system.control_job(self.op, j["id"], "resume")

    def test_pause_and_cancel_running_via_heartbeat(self):
        j = self.submit()
        lease = self.system.claim("w1")
        self.system.control_job(self.op, j["id"], "pause")
        self.assertEqual(self.system.heartbeat(lease), "pause")
        self.assertEqual(self.system.finish(lease, ok=True), "paused")
        self.system.control_job(self.op, j["id"], "resume")
        lease = self.system.claim("w1")
        self.system.control_job(self.op, j["id"], "cancel")
        self.assertEqual(self.system.finish(lease, ok=True), "cancelled")

    def test_model_change_refused_while_running(self):
        j = self.submit()
        self.system.change_model(self.admin, j["id"], "mock", "mock-reviewer-1")
        self.system.claim("w1")
        with self.assertRaises(Conflict):
            self.system.change_model(self.admin, j["id"], "mock", "mock-analyst-1")
        job = self.system.get_job(self.admin, j["id"])
        self.assertEqual(job["model"], "mock-reviewer-1")


class EmergencyStopTests(SystemCase):
    def test_stop_fences_running_worker_and_blocks_claims(self):
        j = self.system.submit_job(self.admin, function_id="07", instruction="x")
        self.system.submit_job(self.admin, function_id="08", instruction="y")
        lease = self.system.claim("w1")
        self.system.emergency_stop(self.op, "テスト")
        with self.assertRaises(StaleLease):
            self.system.finish(lease, ok=True)
        job = self.system.get_job(self.admin, j["id"])
        self.assertEqual(job["state"], "held")
        self.assertIn("緊急停止", job["hold_reason"])
        self.assertIsNone(self.system.claim("w2"))
        with self.assertRaises(Halted):
            self.system.submit_job(self.admin, function_id="07", instruction="z")

    def test_resume_requires_admin_human_and_valid_audit(self):
        self.system.emergency_stop(self.op, "テスト")
        with self.assertRaises(Forbidden):
            self.system.resume_system(self.op, "x")
        self.system.resume_system(self.admin, "確認済み")
        self.assertFalse(self.system.status()["halted"])
        self.system.submit_job(self.admin, function_id="07", instruction="再開後")
        self.assertIsNotNone(self.system.claim("w1"))

    def test_restart_recovers_after_crash(self):
        """作業者が異常終了 → プロセス再起動 → 監視の reap で復旧。"""
        self.system.submit_job(self.admin, function_id="07", instruction="x")
        self.system.claim("w1")                    # ここで w1 が落ちたと想定
        self.clock.advance(31)
        restarted = self.make_system()             # 新プロセス相当
        self.assertEqual(len(restarted.reap()["requeued"]), 1)
        lease = restarted.claim("w9")
        self.assertEqual(restarted.finish(lease, ok=True), "succeeded")


if __name__ == "__main__":
    unittest.main()
