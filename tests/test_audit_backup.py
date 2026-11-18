import json
import sqlite3
import unittest

from realoria_cc.audit import AuditLog
from realoria_cc.config import Settings
from realoria_cc.core import System
from realoria_cc.db import Store
from realoria_cc.security import Forbidden
from realoria_cc.service import EXIT_AUDIT_FAILED, backup, health, restore

from .helpers import SystemCase


def raw_conn(path):
    c = sqlite3.connect(path, isolation_level=None)
    c.row_factory = sqlite3.Row
    return c


class AuditIntegrityTests(SystemCase):
    def setUp(self):
        super().setUp()
        for i in range(3):
            self.system.submit_job(self.admin, function_id="07", instruction=f"j{i}")
        self.system.anchor()

    def test_clean_chain_verifies(self):
        res = self.system.verify_audit(self.admin)
        self.assertTrue(res.ok, res.problems)
        self.assertGreater(res.entries, 5)

    def test_update_and_delete_blocked_by_trigger(self):
        c = raw_conn(self.settings.db_path)
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE audit_log SET actor='x' WHERE seq=1")
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("DELETE FROM audit_log WHERE seq=1")
        c.close()

    def _tamper(self, sql):
        c = raw_conn(self.settings.db_path)
        c.execute("DROP TRIGGER audit_no_update")
        c.execute("DROP TRIGGER audit_no_delete")
        c.execute(sql)
        c.close()

    def test_detects_modified_detail(self):
        self._tamper("UPDATE audit_log SET detail='{\"forged\":1}' WHERE seq=3")
        res = self.system.verify_audit(self.admin)
        self.assertFalse(res.ok)
        self.assertTrue(any("内容ハッシュ" in p for p in res.problems))

    def test_detects_deleted_middle_entry(self):
        self._tamper("DELETE FROM audit_log WHERE seq=4")
        res = self.system.verify_audit(self.admin)
        self.assertFalse(res.ok)
        self.assertTrue(any("欠番" in p for p in res.problems))

    def test_detects_tail_truncation_via_anchor(self):
        self._tamper("DELETE FROM audit_log WHERE seq >= (SELECT MAX(seq) - 1 FROM audit_log)")
        res = self.system.verify_audit(self.admin)
        self.assertFalse(res.ok)
        self.assertTrue(any("アンカー" in p for p in res.problems))

    def test_detects_recomputed_hash_without_key(self):
        """鍵を持たない攻撃者がハッシュを再計算しても HMAC で検知する。"""
        from realoria_cc.audit import _entry_hash
        c = raw_conn(self.settings.db_path)
        rows = [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY seq")]
        c.close()
        self._tamper("SELECT 1")
        c = raw_conn(self.settings.db_path)
        prev = rows[1]["hash"]
        for r in rows[2:]:
            detail = '{"forged":true}' if r["seq"] == 3 else r["detail"]
            h = _entry_hash(prev, r["seq"], r["ts"], r["actor"], r["action"], r["target"], detail)
            c.execute("UPDATE audit_log SET detail=?, prev_hash=?, hash=? WHERE seq=?",
                      (detail, prev, h, r["seq"]))
            prev = h
        c.close()
        res = self.system.verify_audit(self.admin)
        self.assertFalse(res.ok)
        self.assertTrue(any("HMAC" in p for p in res.problems))

    def test_failure_triggers_safe_stop_and_blocks_resume(self):
        self._tamper("UPDATE audit_log SET actor='mallory' WHERE seq=2")
        self.system.verify_audit(None)
        st = self.system.status()
        self.assertTrue(st["halted"])
        self.assertIsNone(self.system.claim("w1"))
        with self.assertRaises(Forbidden):
            self.system.resume_system(self.admin, "強制再開")
        code, _ = health(self.system)
        self.assertEqual(code, EXIT_AUDIT_FAILED)

    def test_tampered_anchor_line_detected(self):
        lines = self.settings.anchor_path.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[-1])
        rec["seq"] = 1
        lines[-1] = json.dumps(rec)
        self.settings.anchor_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = self.system.verify_audit(self.admin)
        self.assertFalse(res.ok)

    def test_audit_append_requires_transaction(self):
        with self.system.store.read() as c:
            with self.assertRaises(RuntimeError):
                self.system.audit.append(c, 0, "x", "y")


class BackupRestoreTests(SystemCase):
    def test_backup_and_restore_roundtrip(self):
        j = self.system.submit_job(self.admin, function_id="07", instruction="before")
        path = backup(self.system, self.admin)
        self.assertTrue(path.exists())
        self.system.submit_job(self.admin, function_id="07", instruction="after-backup")
        self.system.anchor()
        info = restore(self.settings, path, "admin", clock=self.clock)
        self.assertTrue(info["restored_from"].endswith(".db"))
        restored = System(self.settings, store=Store(self.settings.db_path, self.clock))
        ids = [x["id"] for x in restored.list_jobs(self.admin_in(restored))]
        self.assertEqual(ids, [j["id"]])
        res = restored.verify_audit(None, stop_on_failure=False)
        self.assertTrue(res.ok, res.problems)
        self.assertTrue(restored.status()["halted"])          # 復元後は停止状態
        self.assertTrue(any(self.settings.data_dir.glob("realoria.pre-restore-*.db")))

    def admin_in(self, s):
        from .helpers import PW
        return s.authenticate(s.login("admin", PW))

    def test_backup_requires_admin_human(self):
        with self.assertRaises(Forbidden):
            backup(self.system, self.op)

    def test_restore_rejects_tampered_backup(self):
        path = backup(self.system, self.admin)
        c = raw_conn(path)
        c.execute("DROP TRIGGER audit_no_update")
        c.execute("UPDATE audit_log SET actor='x' WHERE seq=1")
        c.close()
        with self.assertRaises(RuntimeError):
            restore(self.settings, path, "admin", clock=self.clock)


class KeyHandlingTests(unittest.TestCase):
    def test_wrong_key_fails_verification(self):
        import tempfile
        from pathlib import Path
        d = Path(tempfile.mkdtemp())
        s = System(Settings(data_dir=d))
        with s.store.read() as c:
            self.assertTrue(s.audit.verify(c).ok)
            other = AuditLog(b"\x01" * 32, s.settings.anchor_path)
            self.assertFalse(other.verify(c).ok)


if __name__ == "__main__":
    unittest.main()
