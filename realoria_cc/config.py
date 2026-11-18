"""設定。既定値はすべて「安全側」(外部AI無効・ローカルのみ待受・承認無効)。"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

# データ区分 (数値が大きいほど機密)
PUBLIC = 0        # 公開済み情報
INTERNAL = 1      # 内部資料 (運営メモ等)
CONFIDENTIAL = 2  # 機密 (契約・財務・個人情報を含みうる)
RESTRICTED = 3    # 厳秘 (未公開の取材素材・人物保護情報)

CLASSIFICATION_NAMES = {
    PUBLIC: "公開",
    INTERNAL: "内部",
    CONFIDENTIAL: "機密",
    RESTRICTED: "厳秘",
}


@dataclass
class Settings:
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8765
    lease_seconds: float = 60.0
    max_attempts: int = 3
    retry_backoff_seconds: float = 5.0
    session_ttl_seconds: float = 8 * 3600
    # 外部AI (OpenAI / Anthropic) への送信。既定は無効。
    external_ai_enabled: bool = False
    # 外部AIへ送信してよい最大区分。既定は「公開」のみ。
    max_external_classification: int = PUBLIC
    # ローカルLLMへ送信してよい最大区分。
    max_local_classification: int = RESTRICTED
    # 1日あたりのモデル呼出上限 (費用・暴走対策)。
    daily_call_limit: int = 200
    # 1日あたりの費用上限 (USD)。価格未設定のモデルは「費用不明」として拒否する。
    daily_cost_limit_usd: float = 0.0
    # モデル単価 (USD / 1K tokens)。公式価格を確認した上で運用者が設定する。既定は空。
    model_prices: dict = field(default_factory=dict)
    # 監査検証の定期実行間隔 (秒)
    audit_verify_interval_seconds: float = 300.0
    worker_count: int = 2
    # ブラウザ音声入力。Web Speech API は実装によって音声をクラウドへ送るため既定で無効。
    voice_input_enabled: bool = False

    @property
    def db_path(self) -> Path:
        return self.data_dir / "realoria.db"

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @property
    def audit_key_path(self) -> Path:
        return self.secrets_dir / "audit.key"

    @property
    def anchor_path(self) -> Path:
        # 独立監査保全: DB とは別ファイル (将来は別媒体/別ホスト) に追記する。
        return self.data_dir / "anchors" / "audit_anchor.jsonl"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    @classmethod
    def load(cls, data_dir: Path | str) -> "Settings":
        data_dir = Path(data_dir)
        s = cls(data_dir=data_dir)
        p = data_dir / "settings.json"
        if p.exists():
            raw = json.loads(p.read_text(encoding="utf-8"))
            names = {f.name for f in fields(cls)} - {"data_dir"}
            for k, v in raw.items():
                if k in names:
                    setattr(s, k, v)
        return s

    def public_dict(self) -> dict:
        d = asdict(self)
        d["data_dir"] = str(self.data_dir)
        return d
