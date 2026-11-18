"""システム中核: 認証・ジョブ制御・緊急停止・情報源・監査検証を一元化する。

ジョブ制御の不変条件:
  * claim は BEGIN IMMEDIATE 内の条件付き UPDATE で行い、同一ジョブを二重実行しない。
  * claim ごとに lease_token (フェンシングトークン) を単調増加させ、試行ID (attempt_id) を発行。
  * 状態書込みは (attempt_id, lease_token, stop_generation, リース期限) が全て一致する場合のみ成立。
    旧所有者・期限切れ・緊急停止前の世代からの書込みは拒否する (StaleLease)。
  * リース切れジョブは、再試行安全かつ試行回数内なら再キュー、それ以外は Hold に隔離。
  * 緊急停止は stop_generation を進め、実行中ジョブを Hold に移す。再開は人間の管理者のみ・監査検証成功が条件。
"""
from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog, load_or_create_key
from .config import RESTRICTED, Settings
from .db import Store, get_state, set_state
from .org import OrgRegistry
from .providers import PROVIDERS, ModelRouter
from .security import (AuthError, Forbidden, Principal, authorize, check_clearance,
                       hash_password, token_hash, validate_roles, verify_password)


class StaleLease(Exception):
    """リースを失った (旧所有者・期限切れ・停止世代違い) 状態での書込み。"""


class Halted(Exception):
    """緊急停止中。"""


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


TERMINAL = {"succeeded", "failed", "cancelled"}
SYSTEM_ACTOR = "system"


@dataclass
class Lease:
    job_id: str
    attempt_id: str
    token: int
    stop_generation: int
    expires: float


def _job_dict(r) -> dict:
    d = dict(r)
    d["payload"] = json.loads(d["payload"])
    d["result"] = json.loads(d["result"]) if d["result"] else None
    return d


class System:
    def __init__(self, settings: Settings, store: Store | None = None,
                 registry: OrgRegistry | None = None):
        self.settings = settings
        self.store = store or Store(settings.db_path)
        self.store.migrate()
        self.registry = registry or OrgRegistry.load()
        self.audit = AuditLog(load_or_create_key(settings.audit_key_path), settings.anchor_path)
        self.router = ModelRouter(self.store, settings, self.audit)
        self._record_registry_version()

    # ------------------------------------------------------------------ util
    def now(self) -> float:
        return self.store.now()

    def _audit(self, conn, actor: str, action: str, target: str | None = None, **detail):
        self.audit.append(conn, self.now(), actor, action, target, detail)

    def anchor(self, kind: str = "checkpoint") -> None:
        with self.store.read() as conn:
            rec = self.audit.write_anchor(conn, self.now(), kind)
        if rec:
            self._anchored_seq = rec["seq"]

    def anchor_if_changed(self) -> None:
        """監視ループから呼ぶ。前回アンカー以降に監査が進んでいれば外部アンカーを追記。"""
        with self.store.read() as conn:
            row = conn.execute("SELECT MAX(seq) FROM audit_log").fetchone()
        if row[0] and row[0] != getattr(self, "_anchored_seq", None):
            self.anchor()

    def notify(self, conn, level: str, message: str) -> None:
        conn.execute("INSERT INTO notifications (level, message, created_at) VALUES (?,?,?)",
                     (level, message, self.now()))

    def _record_registry_version(self) -> None:
        with self.store.tx() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key='registry_sha256'").fetchone()
            if row and row["value"] == self.registry.sha256:
                return
            conn.execute("INSERT INTO meta (key, value) VALUES ('registry_sha256', ?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (self.registry.sha256,))
            self._audit(conn, SYSTEM_ACTOR, "registry.loaded", self.registry.version,
                        sha256=self.registry.sha256, verified=self.registry.verified)
        self.anchor()

    # ------------------------------------------------------------ principals
    def create_principal(self, actor: Principal | None, pid: str, kind: str, display_name: str,
                         roles: set[str], clearance: int, password: str | None = None,
                         bootstrap: bool = False) -> None:
        if not bootstrap:
            authorize(actor, "user.manage")
        validate_roles(kind, roles)
        if kind == "human" and not password:
            raise ValueError("人間主体にはパスワードが必要です")
        if kind != "human" and password:
            raise ValueError("AI/システム主体はパスワードでログインできません")
        pw = hash_password(password) if password else None
        with self.store.tx() as conn:
            if bootstrap:
                n = conn.execute("SELECT COUNT(*) FROM principals WHERE kind='human'").fetchone()[0]
                if n:
                    raise Forbidden("初期管理者は既に存在します")
            conn.execute(
                "INSERT INTO principals (id, kind, display_name, password_hash, roles, clearance,"
                " created_at) VALUES (?,?,?,?,?,?,?)",
                (pid, kind, display_name, pw, json.dumps(sorted(roles)), clearance, self.now()))
            self._audit(conn, actor.id if actor else "bootstrap", "principal.create", pid,
                        kind=kind, roles=sorted(roles), clearance=clearance)

    def get_principal(self, pid: str) -> Principal:
        with self.store.read() as conn:
            r = conn.execute("SELECT * FROM principals WHERE id=?", (pid,)).fetchone()
        if not r:
            raise NotFound(pid)
        return Principal(r)

    def login(self, pid: str, password: str) -> str:
        now = self.now()
        with self.store.tx() as conn:
            r = conn.execute("SELECT * FROM principals WHERE id=?", (pid,)).fetchone()
            ok = bool(r) and r["kind"] == "human" and bool(r["enabled"]) \
                and r["locked_until"] <= now and verify_password(password, r["password_hash"])
            if not ok:
                if r:
                    fails = r["failed_logins"] + 1
                    lock = now + 900 if fails >= 5 else r["locked_until"]
                    conn.execute("UPDATE principals SET failed_logins=?, locked_until=? WHERE id=?",
                                 (fails, lock, pid))
                self._audit(conn, pid or "?", "auth.login_failed", pid)
                # ロールバックさせず失敗記録を残すため、例外は tx 終了後に送出
                failed = True
            else:
                failed = False
                token = secrets.token_urlsafe(32)
                conn.execute("UPDATE principals SET failed_logins=0, locked_until=0 WHERE id=?", (pid,))
                conn.execute("INSERT INTO sessions (token_hash, principal_id, created_at, expires_at)"
                             " VALUES (?,?,?,?)",
                             (token_hash(token), pid, now, now + self.settings.session_ttl_seconds))
                self._audit(conn, pid, "auth.login", pid)
        if failed:
            raise AuthError("IDまたはパスワードが正しくないか、ロックされています")
        return token

    def authenticate(self, token: str | None) -> Principal:
        if not token:
            raise AuthError("未認証です")
        with self.store.read() as conn:
            r = conn.execute(
                "SELECT p.* FROM sessions s JOIN principals p ON p.id = s.principal_id "
                "WHERE s.token_hash=? AND s.revoked=0 AND s.expires_at>?",
                (token_hash(token), self.now())).fetchone()
        if not r or not r["enabled"]:
            raise AuthError("セッションが無効です")
        return Principal(r)

    def logout(self, token: str) -> None:
        with self.store.tx() as conn:
            conn.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (token_hash(token),))

    # --------------------------------------------------------------- sources
    def register_source(self, actor: Principal, sid: str, title: str, version: str,
                        status: str, classification: int, content: str) -> dict:
        authorize(actor, "source.register")
        check_clearance(actor, classification)
        if status == "official":
            # 正式情報源の登録・改訂は人間の正式承認を要する。承認機能は未有効のため拒否。
            raise Forbidden("正式情報源の登録は正式承認手続きが未照合のため無効化されています")
        sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        with self.store.tx() as conn:
            if conn.execute("SELECT 1 FROM sources WHERE id=?", (sid,)).fetchone():
                raise Conflict("同じIDの情報源が既にあります (改訂は新IDで登録)")
            conn.execute("INSERT INTO sources (id, title, version, status, classification, content,"
                         " sha256, registered_by, registered_at) VALUES (?,?,?,?,?,?,?,?,?)",
                         (sid, title, version, status, classification, content, sha, actor.id,
                          self.now()))
            self._audit(conn, actor.id, "source.register", sid, version=version, status=status,
                        classification=classification, sha256=sha)
        return {"id": sid, "sha256": sha}

    def list_sources(self, actor: Principal) -> list[dict]:
        authorize(actor, "source.read")
        with self.store.read() as conn:
            rows = conn.execute("SELECT id, title, version, status, classification, sha256,"
                                " registered_at FROM sources WHERE classification<=? ORDER BY id",
                                (actor.clearance,)).fetchall()
        return [dict(r) for r in rows]

    def _load_sources(self, conn, ids: list[str]) -> list:
        rows = []
        for sid in ids:
            r = conn.execute("SELECT * FROM sources WHERE id=?", (sid,)).fetchone()
            if not r:
                raise NotFound(f"情報源 {sid}")
            rows.append(r)
        return rows

    # ------------------------------------------------------------------ jobs
    def submit_job(self, actor: Principal, *, function_id: str, instruction: str,
                   source_ids: list[str] | None = None, classification: int = 0,
                   provider: str = "mock", model: str = "mock-analyst-1",
                   output_kind: str = "analysis", idempotency_key: str | None = None,
                   retry_safe: bool = True) -> dict:
        authorize(actor, "job.submit")
        try:
            self.registry.function(function_id)
        except KeyError:
            raise NotFound(f"基幹機能 {function_id}") from None
        if not self.registry.allowed_output(function_id, output_kind):
            raise Forbidden(f"機能{function_id}は {output_kind} を出力できません (Signal限定)")
        if provider not in PROVIDERS or model not in PROVIDERS[provider].models:
            raise Forbidden("未登録のプロバイダ/モデルです")
        if not 0 <= classification <= RESTRICTED:
            raise ValueError("情報区分が不正です")
        if len(instruction) > 20000:
            raise ValueError("指示が長すぎます")
        source_ids = list(source_ids or [])
        now = self.now()
        with self.store.tx() as conn:
            if get_state(conn, "halted") == "1":
                raise Halted("緊急停止中のため受付できません")
            if idempotency_key:
                r = conn.execute("SELECT * FROM jobs WHERE idempotency_key=?",
                                 (idempotency_key,)).fetchone()
                if r:
                    return _job_dict(r)
            srcs = self._load_sources(conn, source_ids)
            # ジョブ区分 = 宣言区分と参照資料の最大値 (下げられない)
            cls = max([classification] + [s["classification"] for s in srcs])
            check_clearance(actor, cls)
            jid = uuid.uuid4().hex
            payload = {"instruction": instruction, "source_ids": source_ids,
                       "output_kind": output_kind}
            conn.execute(
                "INSERT INTO jobs (id, idempotency_key, kind, function_id, payload, classification,"
                " provider, model, state, retry_safe, max_attempts, next_run_at, created_by,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,'queued',?,?,?,?,?,?)",
                (jid, idempotency_key, "agent_analysis", function_id, json.dumps(payload,
                 ensure_ascii=False), cls, provider, model, int(retry_safe),
                 self.settings.max_attempts, now, actor.id, now, now))
            self._audit(conn, actor.id, "job.submit", jid, function_id=function_id,
                        classification=cls, provider=provider, model=model,
                        instruction_sha256=hashlib.sha256(instruction.encode()).hexdigest(),
                        source_ids=source_ids)
            r = conn.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        return _job_dict(r)

    def get_job(self, actor: Principal, jid: str) -> dict:
        authorize(actor, "job.read")
        with self.store.read() as conn:
            r = conn.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
            if not r:
                raise NotFound(jid)
            check_clearance(actor, r["classification"])
            d = _job_dict(r)
            d["proposals"] = [dict(p, content=json.loads(p["content"]),
                                   grounding=json.loads(p["grounding"]))
                              for p in conn.execute("SELECT * FROM proposals WHERE job_id=?"
                                                    " ORDER BY created_at", (jid,))]
            d["model_calls"] = [dict(c) for c in conn.execute(
                "SELECT * FROM model_calls WHERE job_id=? ORDER BY created_at", (jid,))]
        return d

    def list_jobs(self, actor: Principal, limit: int = 50) -> list[dict]:
        authorize(actor, "job.read")
        with self.store.read() as conn:
            rows = conn.execute("SELECT id, function_id, state, provider, model, classification,"
                                " attempts, max_attempts, hold_reason, error, created_by,"
                                " created_at, updated_at FROM jobs WHERE classification<=?"
                                " ORDER BY created_at DESC LIMIT ?",
                                (actor.clearance, limit)).fetchall()
        return [dict(r) for r in rows]

    def control_job(self, actor: Principal, jid: str, op: str, reason: str = "") -> dict:
        perm = "job.release_hold" if op == "release" else "job.control"
        authorize(actor, perm)
        now = self.now()
        with self.store.tx() as conn:
            r = conn.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
            if not r:
                raise NotFound(jid)
            check_clearance(actor, r["classification"])
            st = r["state"]
            if op == "pause":
                if st == "queued":
                    new = ("paused", None)
                elif st == "running":
                    new = (st, "pause")  # 次のハートビートで作業者が停止
                else:
                    raise Conflict(f"{st} のジョブは一時停止できません")
            elif op == "resume":
                if st != "paused":
                    raise Conflict("一時停止中のジョブのみ再開できます")
                if get_state(conn, "halted") == "1":
                    raise Halted("緊急停止中です")
                new = ("queued", None)
            elif op == "cancel":
                if st in TERMINAL:
                    raise Conflict("終了済みです")
                new = (st, "cancel") if st == "running" else ("cancelled", None)
            elif op == "release":
                if st != "held":
                    raise Conflict("Hold 中のジョブのみ解除できます")
                if get_state(conn, "halted") == "1":
                    raise Halted("緊急停止中です")
                # 解除は人間が状態を確認した上で、試行回数をリセットせず1回分だけ再実行を許す
                conn.execute("UPDATE jobs SET max_attempts = MAX(max_attempts, attempts + 1)"
                             " WHERE id=?", (jid,))
                new = ("queued", None)
            else:
                raise ValueError(op)
            conn.execute("UPDATE jobs SET state=?, control=?, hold_reason=CASE WHEN ?='queued'"
                         " THEN NULL ELSE hold_reason END, next_run_at=?, updated_at=? WHERE id=?",
                         (new[0], new[1], new[0], now, now, jid))
            self._audit(conn, actor.id, f"job.{op}", jid, from_state=st, to_state=new[0],
                        control=new[1], reason=reason)
        return self.get_job(actor, jid)

    def change_model(self, actor: Principal, jid: str, provider: str, model: str) -> dict:
        """実行中ジョブのモデルは変更しない。待機/一時停止中のみ、人間の操作で変更可。"""
        authorize(actor, "job.change_model")
        if provider not in PROVIDERS or model not in PROVIDERS[provider].models:
            raise Forbidden("未登録のプロバイダ/モデルです")
        with self.store.tx() as conn:
            r = conn.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
            if not r:
                raise NotFound(jid)
            if r["state"] not in ("queued", "paused"):
                raise Conflict(f"{r['state']} のジョブのモデルは変更できません")
            conn.execute("UPDATE jobs SET provider=?, model=?, updated_at=? WHERE id=?",
                         (provider, model, self.now(), jid))
            self._audit(conn, actor.id, "job.change_model", jid,
                        before=f"{r['provider']}:{r['model']}", after=f"{provider}:{model}")
        return self.get_job(actor, jid)

    # --------------------------------------------------------- lease protocol
    def claim(self, worker_id: str) -> Lease | None:
        now = self.now()
        with self.store.tx() as conn:
            if get_state(conn, "halted") == "1":
                return None
            gen = int(get_state(conn, "stop_generation"))
            r = conn.execute("SELECT id FROM jobs WHERE state='queued' AND next_run_at<=?"
                             " ORDER BY next_run_at, created_at LIMIT 1", (now,)).fetchone()
            if not r:
                return None
            attempt_id = f"{worker_id}:{uuid.uuid4().hex[:12]}"
            expires = now + self.settings.lease_seconds
            cur = conn.execute(
                "UPDATE jobs SET state='running', lease_owner=?, lease_token=lease_token+1,"
                " lease_expires=?, stop_generation=?, attempts=attempts+1, updated_at=?"
                " WHERE id=? AND state='queued'",
                (attempt_id, expires, gen, now, r["id"]))
            if cur.rowcount != 1:
                return None
            tok = conn.execute("SELECT lease_token FROM jobs WHERE id=?", (r["id"],)).fetchone()[0]
            self._audit(conn, SYSTEM_ACTOR, "job.claim", r["id"], attempt_id=attempt_id,
                        lease_token=tok, stop_generation=gen)
        return Lease(r["id"], attempt_id, tok, gen, expires)

    def _check_lease(self, conn, lease: Lease):
        r = conn.execute("SELECT * FROM jobs WHERE id=?", (lease.job_id,)).fetchone()
        gen = int(get_state(conn, "stop_generation"))
        if (r is None or r["state"] != "running" or r["lease_owner"] != lease.attempt_id
                or r["lease_token"] != lease.token or r["stop_generation"] != lease.stop_generation
                or gen != lease.stop_generation or r["lease_expires"] <= self.now()):
            raise StaleLease(f"リース喪失: job={lease.job_id} attempt={lease.attempt_id}")
        return r

    def heartbeat(self, lease: Lease) -> str | None:
        """リース延長。戻り値は制御要求 ('pause' | 'cancel' | None)。"""
        with self.store.tx() as conn:
            r = self._check_lease(conn, lease)
            lease.expires = self.now() + self.settings.lease_seconds
            conn.execute("UPDATE jobs SET lease_expires=?, updated_at=? WHERE id=?",
                         (lease.expires, self.now(), lease.job_id))
            return r["control"]

    def finish(self, lease: Lease, *, ok: bool, result: dict | None = None,
               error: str | None = None, proposals: list[dict] | None = None,
               retryable: bool = True) -> str:
        now = self.now()
        with self.store.tx() as conn:
            r = self._check_lease(conn, lease)
            if r["control"] == "cancel":
                state, nra = "cancelled", now
            elif r["control"] == "pause":
                state, nra = "paused", now
            elif ok:
                state, nra = "succeeded", now
            elif retryable and r["retry_safe"] and r["attempts"] < r["max_attempts"]:
                backoff = self.settings.retry_backoff_seconds * (2 ** (r["attempts"] - 1))
                state, nra = "queued", now + backoff
            elif retryable and r["retry_safe"]:
                state, nra = "failed", now
            else:
                state, nra = "held", now
            hold = None if state != "held" else "再試行不可の失敗 (人間の確認が必要)"
            conn.execute("UPDATE jobs SET state=?, control=NULL, lease_owner=NULL,"
                         " lease_expires=NULL, next_run_at=?, result=?, error=?, hold_reason=?,"
                         " updated_at=? WHERE id=?",
                         (state, nra, json.dumps(result, ensure_ascii=False) if result else None,
                          error, hold, now, lease.job_id))
            if state == "succeeded":
                for p in proposals or []:
                    conn.execute("INSERT INTO proposals (id, job_id, function_id, kind, status,"
                                 " content, grounding, created_at) VALUES (?,?,?,?,?,?,?,?)",
                                 (uuid.uuid4().hex, lease.job_id, r["function_id"], p["kind"],
                                  p["status"], json.dumps(p["content"], ensure_ascii=False),
                                  json.dumps(p["grounding"], ensure_ascii=False), now))
            self._audit(conn, SYSTEM_ACTOR, "job.finish", lease.job_id,
                        attempt_id=lease.attempt_id, lease_token=lease.token, state=state,
                        error=error)
            if state in ("failed", "held"):
                self.notify(conn, "warning", f"ジョブ {lease.job_id[:8]} が {state} になりました: {error}")
        return state

    def reap(self) -> dict:
        """期限切れリース・旧停止世代の実行中ジョブを回収する (異常終了後の復旧)。"""
        now = self.now()
        out = {"requeued": [], "held": []}
        with self.store.tx() as conn:
            gen = int(get_state(conn, "stop_generation"))
            rows = conn.execute("SELECT * FROM jobs WHERE state='running' AND"
                                " (lease_expires<=? OR stop_generation<>?)", (now, gen)).fetchall()
            for r in rows:
                stale_gen = r["stop_generation"] != gen
                if r["control"] == "cancel":
                    state, reason = "cancelled", None
                elif r["control"] == "pause" and not stale_gen:
                    state, reason = "paused", None
                elif (not stale_gen and r["retry_safe"] and r["attempts"] < r["max_attempts"]):
                    state, reason = "queued", None
                else:
                    state = "held"
                    reason = ("緊急停止により中断" if stale_gen else
                              "孤立ジョブ (リース切れ・再試行不可または上限到達)")
                conn.execute("UPDATE jobs SET state=?, control=NULL, lease_owner=NULL,"
                             " lease_expires=NULL, hold_reason=?, next_run_at=?, updated_at=?"
                             " WHERE id=? AND state='running' AND lease_token=?",
                             (state, reason, now, now, r["id"], r["lease_token"]))
                self._audit(conn, SYSTEM_ACTOR, "job.reap", r["id"], previous_owner=r["lease_owner"],
                            lease_token=r["lease_token"], to_state=state, reason=reason)
                out["requeued" if state == "queued" else "held"].append(r["id"])
                if state == "held":
                    self.notify(conn, "warning", f"ジョブ {r['id'][:8]} を Hold に隔離: {reason}")
        return out

    # --------------------------------------------------------- system state
    def emergency_stop(self, actor: Principal | None, reason: str) -> None:
        if actor is not None:
            authorize(actor, "system.emergency_stop")
        actor_id = actor.id if actor else SYSTEM_ACTOR
        with self.store.tx() as conn:
            gen = int(get_state(conn, "stop_generation")) + 1
            set_state(conn, "halted", "1")
            set_state(conn, "stop_generation", str(gen))
            set_state(conn, "halt_reason", reason)
            self._audit(conn, actor_id, "system.emergency_stop", None, reason=reason,
                        stop_generation=gen)
            self.notify(conn, "critical", f"緊急停止: {reason}")
        self.reap()
        self.anchor()

    def _safe_stop_without_audit(self, reason: str) -> None:
        """監査ログ自体が壊れている場合の停止。監査鎖へ追記せず状態のみ変更する。"""
        with self.store.tx() as conn:
            gen = int(get_state(conn, "stop_generation")) + 1
            set_state(conn, "halted", "1")
            set_state(conn, "stop_generation", str(gen))
            set_state(conn, "halt_reason", reason)
            self.notify(conn, "critical", f"緊急停止 (監査異常): {reason}")

    def resume_system(self, actor: Principal, reason: str) -> None:
        authorize(actor, "system.resume")
        v = self.verify_audit(actor=None, stop_on_failure=False)
        if not v.ok:
            raise Forbidden("監査検証に失敗しているため再開できません")
        with self.store.tx() as conn:
            set_state(conn, "halted", "0")
            set_state(conn, "halt_reason", "")
            self._audit(conn, actor.id, "system.resume", None, reason=reason)
        self.anchor()

    def status(self) -> dict:
        with self.store.read() as conn:
            counts = {r["state"]: r["n"] for r in conn.execute(
                "SELECT state, COUNT(*) AS n FROM jobs GROUP BY state")}
            hb = [dict(r) for r in conn.execute("SELECT * FROM worker_heartbeats")]
            notes = [dict(r) for r in conn.execute(
                "SELECT * FROM notifications ORDER BY id DESC LIMIT 20")]
            last_verify = get_state(conn, "last_audit_verify")
            return {
                "halted": get_state(conn, "halted") == "1",
                "halt_reason": get_state(conn, "halt_reason"),
                "stop_generation": int(get_state(conn, "stop_generation")),
                "job_counts": counts, "workers": hb, "notifications": notes,
                "last_audit_verify": json.loads(last_verify) if last_verify else None,
                "registry": {"version": self.registry.version, "verified": self.registry.verified,
                             "approvals_enabled": self.registry.approvals_enabled},
                "external_ai_enabled": self.settings.external_ai_enabled,
                "now": self.now(),
            }

    def worker_heartbeat(self, worker_id: str, status: str) -> None:
        with self.store.tx() as conn:
            conn.execute("INSERT INTO worker_heartbeats (worker_id, last_seen, status) VALUES (?,?,?)"
                         " ON CONFLICT(worker_id) DO UPDATE SET last_seen=excluded.last_seen,"
                         " status=excluded.status", (worker_id, self.now(), status))

    # ----------------------------------------------------------------- audit
    def verify_audit(self, actor: Principal | None, stop_on_failure: bool = True):
        if actor is not None:
            authorize(actor, "audit.verify")
        with self.store.read() as conn:
            res = self.audit.verify(conn)
        with self.store.tx() as conn:
            set_state(conn, "last_audit_verify", json.dumps(
                {"at": self.now(), **res.as_dict()}, ensure_ascii=False))
        if not res.ok and stop_on_failure:
            # 監査異常時は安全側へ停止する
            self._safe_stop_without_audit("監査ログ検証失敗: " + "; ".join(res.problems[:3]))
        return res

    def read_audit(self, actor: Principal, after: int = 0, limit: int = 100) -> list[dict]:
        authorize(actor, "audit.read")
        with self.store.read() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT seq, ts, actor, action, target, detail, hash FROM audit_log WHERE seq>?"
                " ORDER BY seq LIMIT ?", (after, min(limit, 500)))]

    # --------------------------------------------------------------- approvals
    def decide_approval(self, actor: Principal, proposal_id: str, decision: str) -> None:
        authorize(actor, "approval.decide")
        if not self.registry.approvals_enabled:
            raise Forbidden("正式な承認権限が未照合のため、承認処理は無効化されています")
        raise Forbidden("承認処理は未実装です")  # 照合後に実装する

    @staticmethod
    def init_data_dir(data_dir: Path) -> Settings:
        data_dir.mkdir(parents=True, exist_ok=True)
        return Settings.load(data_dir)
