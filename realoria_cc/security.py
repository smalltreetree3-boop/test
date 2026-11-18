"""認証・認可・データ区分・外部送信ポリシー。

ここでの役割 (role) はシステム操作上の技術的権限であり、REALORIA の正式な
組織権限 (承認権者など) ではない。正式権限は未照合のため実装しない。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3

from .config import CONFIDENTIAL, INTERNAL, PUBLIC, RESTRICTED  # noqa: F401


class AuthError(Exception):
    """未認証 (HTTP 401 相当)。"""


class Forbidden(Exception):
    """権限不足・ポリシー違反 (HTTP 403 相当)。"""


# 操作 → 許可ロール
ACTION_ROLES: dict[str, set[str]] = {
    "org.read": {"viewer", "operator", "admin", "auditor"},
    "job.read": {"viewer", "operator", "admin", "auditor"},
    "job.submit": {"operator", "admin"},
    "job.control": {"operator", "admin"},          # pause / resume / cancel
    "job.release_hold": {"operator", "admin"},     # Hold 隔離の解除
    "job.change_model": {"operator", "admin"},
    "system.emergency_stop": {"operator", "admin"},
    "system.resume": {"admin"},
    "audit.read": {"auditor", "admin"},
    "audit.verify": {"auditor", "admin", "operator"},
    "source.register": {"admin"},
    "source.read": {"viewer", "operator", "admin", "auditor"},
    "user.manage": {"admin"},
    "backup.run": {"admin"},
    "approval.decide": {"approver"},
    "agent.execute": {"agent"},
}

# 人間のみが実行できる操作。AI・system 主体はロールに関係なく拒否する。
HUMAN_ONLY = {
    "job.release_hold", "job.change_model", "system.resume", "user.manage",
    "backup.run", "approval.decide", "source.register",
}

# AI・システム主体が付与されてはならないロール
AI_FORBIDDEN_ROLES = {"admin", "approver", "operator"}

VALID_ROLES = set().union(*ACTION_ROLES.values())


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("パスワードは12文字以上にしてください")
    salt = secrets.token_bytes(16)
    n, r, p = 2**14, 8, 1
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt),
                              n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(dk)))
        return hmac.compare_digest(calc, bytes.fromhex(dk))
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Principal:
    def __init__(self, row: sqlite3.Row | dict):
        self.id: str = row["id"]
        self.kind: str = row["kind"]
        self.display_name: str = row["display_name"]
        self.roles: set[str] = set(json.loads(row["roles"]))
        self.clearance: int = int(row["clearance"])
        self.enabled: bool = bool(row["enabled"])

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "display_name": self.display_name,
                "roles": sorted(self.roles), "clearance": self.clearance}


def authorize(principal: Principal | None, action: str) -> None:
    if principal is None:
        raise AuthError("未認証です")
    if not principal.enabled:
        raise Forbidden("無効化された主体です")
    if action not in ACTION_ROLES:
        raise Forbidden(f"未定義の操作です: {action}")
    if action in HUMAN_ONLY and principal.kind != "human":
        raise Forbidden(f"{action} は人間のみが実行できます")
    if not (principal.roles & ACTION_ROLES[action]):
        raise Forbidden(f"{action} の権限がありません")


def check_clearance(principal: Principal, classification: int) -> None:
    if classification > principal.clearance:
        raise Forbidden("この情報区分を扱う権限がありません")


def validate_roles(kind: str, roles: set[str]) -> None:
    unknown = roles - VALID_ROLES
    if unknown:
        raise ValueError(f"未定義のロール: {sorted(unknown)}")
    if kind != "human" and roles & AI_FORBIDDEN_ROLES:
        raise ValueError("AI/システム主体に人間用ロールは付与できません")
    if kind == "human" and "agent" in roles:
        raise ValueError("人間主体に agent ロールは付与できません")


def egress_allowed(locality: str, classification: int, settings) -> tuple[bool, str]:
    """モデルへの送信可否。locality: 'mock' | 'local' | 'external'。"""
    if locality == "mock":
        return True, "模擬実装 (外部送信なし)"
    if locality == "local":
        if classification <= settings.max_local_classification:
            return True, "ローカルLLM"
        return False, "ローカルLLMの許容区分を超えています"
    if locality == "external":
        if classification >= RESTRICTED:
            return False, "厳秘情報 (未公開取材素材等) は外部AIへ送信できません"
        if not settings.external_ai_enabled:
            return False, "外部AIへの送信は無効化されています (別途承認が必要)"
        if classification > settings.max_external_classification:
            return False, "この情報区分は外部AIへ送信できません"
        return True, "外部AI (許可済み区分)"
    return False, f"不明な接続種別: {locality}"
