"""組織レジストリ (6本部・33基幹機能・3委員会・G1〜G5)。

正式情報源が未提供のため、本部名と番号範囲以外は「未照合」として扱う。
未照合の機能には承認権限を一切付与しない (承認機能は無効化)。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REGISTRY = Path(__file__).parent / "data" / "org_registry.json"
SIGNAL_ONLY_IDS = {"23", "24", "25"}


class RegistryError(ValueError):
    pass


@dataclass
class OrgRegistry:
    raw: dict
    sha256: str

    @classmethod
    def load(cls, path: Path | str = DEFAULT_REGISTRY) -> "OrgRegistry":
        data = Path(path).read_bytes()
        reg = cls(json.loads(data.decode("utf-8")), hashlib.sha256(data).hexdigest())
        reg.validate()
        return reg

    # --- 整合性検査 ----------------------------------------------------------
    def validate(self) -> None:
        hqs = self.raw.get("headquarters", [])
        funcs = self.raw.get("functions", [])
        if len(hqs) != 6:
            raise RegistryError(f"本部数が6ではありません: {len(hqs)}")
        ids = [f["id"] for f in funcs]
        if ids != [f"{i:02d}" for i in range(1, 34)]:
            raise RegistryError("基幹機能IDが01〜33の連番ではありません")
        hq_by_id = {h["id"]: h for h in hqs}
        covered: set[int] = set()
        for h in hqs:
            lo, hi = h["range"]
            rng = set(range(lo, hi + 1))
            if covered & rng:
                raise RegistryError(f"本部範囲が重複: {h['id']}")
            covered |= rng
        if covered != set(range(1, 34)):
            raise RegistryError("本部範囲が01〜33を被覆していません")
        for f in funcs:
            hq = hq_by_id.get(f["hq"])
            if hq is None:
                raise RegistryError(f"機能{f['id']}の所属本部が不明")
            lo, hi = hq["range"]
            if not lo <= int(f["id"]) <= hi:
                raise RegistryError(f"機能{f['id']}が所属本部の範囲外")
            if f["id"] in SIGNAL_ONLY_IDS and set(f["allowed_outputs"]) != {"signal"}:
                raise RegistryError(f"機能{f['id']}はSignal限定であるべきです")
            if f.get("verification") != "verified" and f.get("approval_authority"):
                raise RegistryError(f"未照合の機能{f['id']}に承認権限が設定されています")
        if len(self.raw.get("committees", [])) != 3:
            raise RegistryError("委員会数が3ではありません")
        if [g["id"] for g in self.raw.get("governance", [])] != [f"G{i}" for i in range(1, 6)]:
            raise RegistryError("横断統制G1〜G5が揃っていません")

    # --- 参照 ---------------------------------------------------------------
    @property
    def version(self) -> str:
        return self.raw["registry_version"]

    @property
    def verified(self) -> bool:
        return bool(self.raw.get("verified")) and all(
            f.get("verification") == "verified" for f in self.raw["functions"]
        )

    @property
    def approvals_enabled(self) -> bool:
        """正式権限が照合済みでない限り、承認処理は本番機能として有効化しない。"""
        return self.verified

    def function(self, fid: str) -> dict:
        for f in self.raw["functions"]:
            if f["id"] == fid:
                return f
        raise KeyError(fid)

    def allowed_output(self, fid: str, kind: str) -> bool:
        return kind in self.function(fid)["allowed_outputs"]

    def as_dict(self) -> dict:
        d = dict(self.raw)
        d["sha256"] = self.sha256
        d["approvals_enabled"] = self.approvals_enabled
        return d
