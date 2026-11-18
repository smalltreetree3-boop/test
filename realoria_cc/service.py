"""常時稼働: 作業者 (worker)・監視 (monitor)・健康状態・バックアップ/復元。

33機能のモデルを常時推論させず、ジョブが来た時だけ推論する (イベント駆動 + 定期監視)。
"""
from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import threading
import time
from pathlib import Path

from . import agents
from .audit import AuditLog, load_key
from .core import System
from .security import authorize

log = logging.getLogger("realoria_cc")

# 終了コード (health / verify-audit)
EXIT_OK = 0
EXIT_DEGRADED = 1
EXIT_HALTED = 2
EXIT_AUDIT_FAILED = 3


class Worker(threading.Thread):
    def __init__(self, system: System, worker_id: str, poll: float = 1.0):
        super().__init__(daemon=True, name=worker_id)
        self.system, self.worker_id, self.poll = system, worker_id, poll
        self.stop_evt = threading.Event()

    def run_once(self) -> str | None:
        lease = self.system.claim(self.worker_id)
        if lease is None:
            return None
        return agents.execute(self.system, lease, actor=f"agent:{self.worker_id}")

    def run(self):
        while not self.stop_evt.is_set():
            try:
                self.system.worker_heartbeat(self.worker_id, "running")
                if self.run_once() is None:
                    self.stop_evt.wait(self.poll)
            except Exception:  # 作業者は落とさず記録して継続
                log.exception("worker %s error", self.worker_id)
                self.stop_evt.wait(self.poll)
        self.system.worker_heartbeat(self.worker_id, "stopped")


class Monitor(threading.Thread):
    """リース回収・監査定期検証・作業者の死活監視。"""

    def __init__(self, system: System, interval: float = 5.0):
        super().__init__(daemon=True, name="monitor")
        self.system, self.interval = system, interval
        self.stop_evt = threading.Event()
        self._last_verify = 0.0

    def tick(self) -> None:
        self.system.reap()
        last = self.system.status()["last_audit_verify"]
        if last is None or last.get("ok"):
            # 監査異常の検出後はアンカーを進めない (異常状態を正として固定しないため)
            self.system.anchor_if_changed()
        now = time.monotonic()
        if now - self._last_verify >= self.system.settings.audit_verify_interval_seconds:
            self._last_verify = now
            res = self.system.verify_audit(actor=None, stop_on_failure=True)
            if res.ok:
                self.system.anchor()
            else:
                log.critical("audit verification failed: %s", res.problems)

    def run(self):
        while not self.stop_evt.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("monitor error")
            self.stop_evt.wait(self.interval)


def health(system: System) -> tuple[int, dict]:
    st = system.status()
    checks = {"db": "ok"}
    try:
        with system.store.read() as conn:
            conn.execute("SELECT 1").fetchone()
            ic = conn.execute("PRAGMA quick_check").fetchone()[0]
            checks["db_integrity"] = ic
    except sqlite3.Error as e:
        checks["db"] = f"error: {e}"
    v = st["last_audit_verify"]
    checks["audit"] = "unknown" if v is None else ("ok" if v["ok"] else "failed")
    stale_workers = [w["worker_id"] for w in st["workers"]
                     if w["status"] == "running" and system.now() - w["last_seen"] > 60]
    checks["stale_workers"] = stale_workers
    if checks["audit"] == "failed":
        code = EXIT_AUDIT_FAILED
    elif st["halted"]:
        code = EXIT_HALTED
    elif checks["db"] != "ok" or checks.get("db_integrity") != "ok" or stale_workers:
        code = EXIT_DEGRADED
    else:
        code = EXIT_OK
    return code, {"code": code, "halted": st["halted"], "halt_reason": st["halt_reason"],
                  "checks": checks, "job_counts": st["job_counts"]}


# ---------------------------------------------------------------- backup
def backup(system: System, actor) -> Path:
    authorize(actor, "backup.run")
    system.settings.backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(system.now()))
    dest = system.settings.backup_dir / f"realoria-{stamp}.db"
    src = system.store.connect()
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    # バックアップ自体の監査鎖を検証 (アンカーは現行DB用のため除外して鎖のみ確認)
    chk = AuditLog(system.audit.key, dest.with_suffix(".noanchor"))
    c = sqlite3.connect(dest)
    c.row_factory = sqlite3.Row
    try:
        res = chk.verify(c)
    finally:
        c.close()
    if not res.ok:
        dest.unlink(missing_ok=True)
        raise RuntimeError(f"バックアップの監査検証に失敗: {res.problems[:3]}")
    meta = {"created_at": system.now(), "audit_last_seq": res.last_seq,
            "registry_sha256": system.registry.sha256}
    dest.with_suffix(".json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    with system.store.tx() as conn:
        system._audit(conn, actor.id, "backup.create", dest.name, audit_last_seq=res.last_seq)
    system.anchor()
    return dest


def restore(settings, backup_path: Path, actor_id: str, clock=time.time) -> dict:
    """サービス停止中に実行する。現行DBは退避し、復元後に restore アンカーを打つ。

    復元はロールバックを伴うため、外部アンカー上で restore 区切りを明示して記録する。
    """
    backup_path = Path(backup_path)
    key = load_key(settings.audit_key_path)
    c = sqlite3.connect(backup_path)
    c.row_factory = sqlite3.Row
    try:
        res = AuditLog(key, backup_path.with_suffix(".noanchor")).verify(c)
    finally:
        c.close()
    if not res.ok:
        raise RuntimeError(f"復元元の監査検証に失敗: {res.problems[:3]}")
    db = settings.db_path
    if db.exists():
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(clock()))
        quarantine = db.with_name(f"realoria.pre-restore-{stamp}.db")
        shutil.move(str(db), quarantine)
        for ext in ("-wal", "-shm"):
            p = Path(str(db) + ext)
            if p.exists():
                shutil.move(str(p), str(quarantine) + ext)
    shutil.copy2(backup_path, db)
    from .db import Store
    store = Store(db, clock)
    audit = AuditLog(key, settings.anchor_path)
    with store.tx() as conn:
        # 復元後は停止状態で起動し、人間が確認してから再開する
        from .db import get_state, set_state
        gen = int(get_state(conn, "stop_generation") or 0) + 1
        set_state(conn, "halted", "1")
        set_state(conn, "stop_generation", str(gen))
        set_state(conn, "halt_reason", f"バックアップから復元: {backup_path.name}")
        audit.append(conn, clock(), actor_id, "system.restore", backup_path.name,
                     {"restored_last_seq": res.last_seq})
    with store.read() as conn:
        audit.write_anchor(conn, clock(), kind="restore")
    return {"restored_from": str(backup_path), "audit_last_seq": res.last_seq + 1}
