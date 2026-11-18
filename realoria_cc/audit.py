"""改ざん検知可能な監査ログ。

三層で保全する:
  1. DB トリガーで UPDATE/DELETE を拒否 (通常経路での改変防止)
  2. ハッシュ鎖 + HMAC (鍵は DB 外) で改変・欠落・順序入替を検知
  3. 外部アンカーファイル (追記専用 JSONL) で末尾切り詰め・巻き戻しを検知

監査追記は業務処理と同一トランザクションで行うため、監査が書けない操作は成立しない。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

GENESIS = "0" * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _entry_hash(prev_hash: str, seq: int, ts: float, actor: str, action: str,
                target: str | None, detail: str) -> str:
    body = canonical([prev_hash, seq, repr(float(ts)), actor, action, target or "", detail])
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = bytes.fromhex(path.read_text(encoding="ascii").strip())
        if len(key) < 32:
            raise ValueError("audit key too short")
        return key
    key = secrets.token_bytes(32)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(key.hex(), encoding="ascii")
    try:
        os.chmod(tmp, 0o600)  # Windows では読取専用属性のみ。ACL 設定は運用手順で行う。
    except OSError:
        pass
    os.replace(tmp, path)
    return key


def load_key(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"監査鍵がありません: {path}")
    return bytes.fromhex(path.read_text(encoding="ascii").strip())


class AuditLog:
    def __init__(self, key: bytes, anchor_path: Path):
        self.key = key
        self.anchor_path = anchor_path

    def _mac(self, h: str) -> str:
        return hmac.new(self.key, h.encode("ascii"), hashlib.sha256).hexdigest()

    def append(self, conn: sqlite3.Connection, ts: float, actor: str, action: str,
               target: str | None = None, detail: dict | None = None) -> int:
        """呼出側トランザクション (BEGIN IMMEDIATE) 内で呼ぶこと。"""
        if not conn.in_transaction:
            raise RuntimeError("audit.append must run inside a transaction")
        row = conn.execute(
            "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = row["hash"] if row else GENESIS
        seq = (row["seq"] + 1) if row else 1
        d = canonical(detail or {})
        h = _entry_hash(prev_hash, seq, ts, actor, action, target, d)
        conn.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, target, detail, prev_hash, hash, mac)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (seq, ts, actor, action, target, d, prev_hash, h, self._mac(h)),
        )
        return seq

    # --- 外部アンカー -------------------------------------------------------
    def write_anchor(self, conn: sqlite3.Connection, ts: float, kind: str = "checkpoint") -> dict | None:
        """コミット後に呼ぶ。最新 seq/hash を DB 外ファイルへ追記する。"""
        row = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        if not row:
            return None
        rec = {"kind": kind, "seq": row["seq"], "hash": row["hash"], "ts": ts}
        rec["mac"] = self._mac(canonical([rec["kind"], rec["seq"], rec["hash"], repr(float(ts))]))
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.anchor_path, "a", encoding="utf-8") as f:
            f.write(canonical(rec) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return rec

    def _read_anchors(self) -> tuple[list[dict], list[str]]:
        problems: list[str] = []
        anchors: list[dict] = []
        if not self.anchor_path.exists():
            return anchors, problems
        for i, line in enumerate(self.anchor_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                expect = self._mac(canonical([rec["kind"], rec["seq"], rec["hash"], repr(float(rec["ts"]))]))
                if not hmac.compare_digest(expect, rec.get("mac", "")):
                    problems.append(f"アンカー{i}行目の署名不一致")
                    continue
                anchors.append(rec)
            except (ValueError, KeyError, TypeError):
                problems.append(f"アンカー{i}行目の形式不正")
        return anchors, problems

    # --- 検証 ---------------------------------------------------------------
    def verify(self, conn: sqlite3.Connection) -> "VerifyResult":
        res = VerifyResult()
        prev_hash = GENESIS
        expected_seq = 1
        hashes: dict[int, str] = {}
        for r in conn.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
            seq = r["seq"]
            if seq != expected_seq:
                res.problems.append(f"欠番: seq {expected_seq} が無く {seq} が出現")
                expected_seq = seq
            if r["prev_hash"] != prev_hash:
                res.problems.append(f"seq {seq}: 直前ハッシュ不一致 (削除・入替の可能性)")
            h = _entry_hash(r["prev_hash"], seq, r["ts"], r["actor"], r["action"], r["target"], r["detail"])
            if h != r["hash"]:
                res.problems.append(f"seq {seq}: 内容ハッシュ不一致 (改変の可能性)")
            if not hmac.compare_digest(self._mac(r["hash"]), r["mac"]):
                res.problems.append(f"seq {seq}: HMAC 不一致 (鍵なし再計算の可能性)")
            hashes[seq] = r["hash"]
            prev_hash = r["hash"]
            expected_seq = seq + 1
            res.entries += 1
        res.last_seq = expected_seq - 1
        anchors, aprob = self._read_anchors()
        res.problems.extend(aprob)
        # 最後の restore 以降のアンカーのみが現行 DB と対応する
        last_restore = max((i for i, a in enumerate(anchors) if a["kind"] == "restore"), default=-1)
        active = anchors[last_restore:] if last_restore >= 0 else anchors
        for a in active:
            if a["seq"] > res.last_seq:
                res.problems.append(
                    f"アンカー seq {a['seq']} が DB 末尾 {res.last_seq} を超過 (切り詰め・巻き戻しの可能性)"
                )
            elif hashes.get(a["seq"]) != a["hash"]:
                res.problems.append(f"アンカー seq {a['seq']} のハッシュが DB と不一致")
        res.anchor_count = len(active)
        return res


@dataclass
class VerifyResult:
    entries: int = 0
    last_seq: int = 0
    anchor_count: int = 0
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def as_dict(self) -> dict:
        return {"ok": self.ok, "entries": self.entries, "last_seq": self.last_seq,
                "anchor_count": self.anchor_count, "problems": self.problems}
