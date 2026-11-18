"""AIモデル接続層。

- Provider インターフェースで OpenAI / Anthropic / ローカルLLM / 模擬 を差し替え可能にする。
- 現段階では実API接続を行わない。外部プロバイダは「未実装・無効」で必ず例外を返す。
- 送信可否 (データ区分)・日次上限・費用上限・送信記録はルーター側で一元管理する。
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass

from .security import egress_allowed


class ProviderUnavailable(Exception):
    pass


class EgressDenied(Exception):
    pass


class BudgetExceeded(Exception):
    pass


@dataclass
class ModelResponse:
    text: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    tokens_estimated: bool = True


class Provider:
    name = "base"
    label = "base"
    locality = "external"   # 'mock' | 'local' | 'external'
    models: tuple[str, ...] = ()
    implemented = False

    def complete(self, system: str, prompt: str, model: str) -> ModelResponse:
        raise ProviderUnavailable(f"{self.label} は未接続です")

    def describe(self, settings) -> dict:
        enabled, reason = self.available(settings)
        return {"name": self.name, "label": self.label, "locality": self.locality,
                "models": list(self.models), "enabled": enabled, "reason": reason}

    def available(self, settings) -> tuple[bool, str]:
        if not self.implemented:
            return False, "接続未実装 (実API接続は別途承認対象)"
        if self.locality == "external" and not settings.external_ai_enabled:
            return False, "外部AI送信が無効"
        return True, "利用可"


class OpenAIProvider(Provider):
    # モデル名は運用時に公式ドキュメントで確認して設定する。ここでは識別子の枠のみ。
    name, label, locality = "openai", "OpenAI", "external"
    models = ("(未設定)",)


class AnthropicProvider(Provider):
    name, label, locality = "anthropic", "Claude (Anthropic)", "external"
    models = ("(未設定)",)


class LocalLLMProvider(Provider):
    # 例: Ollama / llama.cpp server 等。ローカル待受への接続は将来実装。
    name, label, locality = "local", "ローカルAI", "local"
    models = ("(未設定)",)


class MockProvider(Provider):
    """決定的な模擬応答。根拠 (source id) 付きの JSON を返す。

    指示文に [[fabricate]] を含めると、根拠のない主張を混入させる (捏造検知テスト用)。
    """
    name, label, locality = "mock", "模擬AI (オフライン)", "mock"
    models = ("mock-analyst-1", "mock-reviewer-1")
    implemented = True

    _SRC = re.compile(r"<source id=\"([^\"]+)\"[^>]*>\n(.*?)\n</source>", re.S)

    def complete(self, system: str, prompt: str, model: str) -> ModelResponse:
        sources = self._SRC.findall(prompt)
        if model == "mock-reviewer-1":
            out = {"verdict": "pass", "notes": ["模擬レビュー: 根拠付きの記述のみを確認"]}
        else:
            findings = []
            for sid, body in sources:
                first = re.split(r"(?<=[。．.!?！？])", body.strip(), maxsplit=1)[0][:120]
                if first:
                    findings.append({"text": f"資料の記載: {first}", "source_ids": [sid]})
            unknowns = [] if sources else ["根拠資料が指定されていないため確認できません"]
            if "[[fabricate]]" in prompt:
                findings.append({"text": "読者数は前年比300%増加した", "source_ids": []})
                findings.append({"text": "架空資料に基づく主張", "source_ids": ["no-such-source"]})
            out = {"summary": f"模擬分析: 資料{len(sources)}件を参照", "findings": findings,
                   "unknowns": unknowns, "proposals": []}
        text = json.dumps(out, ensure_ascii=False)
        return ModelResponse(text=text, input_tokens=len(prompt) // 2,
                             output_tokens=len(text) // 2, tokens_estimated=True)


PROVIDERS: dict[str, Provider] = {
    p.name: p for p in (MockProvider(), OpenAIProvider(), AnthropicProvider(), LocalLLMProvider())
}


class ModelRouter:
    def __init__(self, store, settings, audit):
        self.store = store
        self.settings = settings
        self.audit = audit

    def _day_usage(self, conn) -> tuple[int, float]:
        since = self.store.now() - 86400
        row = conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(SUM(cost_usd), 0) AS c FROM model_calls "
            "WHERE created_at >= ? AND status = 'ok'", (since,)).fetchone()
        return int(row["n"]), float(row["c"])

    def _price(self, provider: Provider, model: str) -> float | None:
        if provider.locality in ("mock", "local"):
            return 0.0
        p = self.settings.model_prices.get(f"{provider.name}:{model}")
        return float(p) if p is not None else None

    def call(self, *, provider_name: str, model: str, system: str, prompt: str,
             classification: int, job_id: str | None, attempt_id: str | None,
             actor: str) -> ModelResponse:
        provider = PROVIDERS.get(provider_name)
        if provider is None:
            raise ProviderUnavailable(f"不明なプロバイダ: {provider_name}")
        if model not in provider.models:
            raise ProviderUnavailable(f"{provider.label} に未登録のモデル: {model}")
        prompt_sha = hashlib.sha256((system + "\n" + prompt).encode("utf-8")).hexdigest()
        call_id = uuid.uuid4().hex
        now = self.store.now()

        def record(conn, status, resp=None, cost=None):
            conn.execute(
                "INSERT INTO model_calls (id, job_id, attempt_id, provider, model, locality,"
                " classification, prompt_sha256, prompt_chars, output_chars, input_tokens,"
                " output_tokens, tokens_estimated, cost_usd, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (call_id, job_id, attempt_id, provider.name, model, provider.locality,
                 classification, prompt_sha, len(prompt), len(resp.text) if resp else 0,
                 resp.input_tokens if resp else None, resp.output_tokens if resp else None,
                 int(resp.tokens_estimated) if resp else 1, cost, status, now))
            self.audit.append(conn, now, actor, "model.call", job_id, {
                "call_id": call_id, "provider": provider.name, "model": model,
                "locality": provider.locality, "classification": classification,
                "prompt_sha256": prompt_sha, "status": status})

        # 送信前検査 (拒否も記録する)
        with self.store.tx() as conn:
            ok, reason = provider.available(self.settings)
            denial = None
            if not ok:
                denial = ("unavailable", ProviderUnavailable(reason))
            else:
                ok, reason = egress_allowed(provider.locality, classification, self.settings)
                if not ok:
                    denial = ("egress_denied", EgressDenied(reason))
            if denial is None:
                n, cost = self._day_usage(conn)
                price = self._price(provider, model)
                if n >= self.settings.daily_call_limit:
                    denial = ("budget_denied", BudgetExceeded("1日の呼出上限に達しました"))
                elif price is None:
                    denial = ("budget_denied", BudgetExceeded("モデル単価が未設定のため費用を管理できません"))
                elif price > 0 and cost >= self.settings.daily_cost_limit_usd:
                    denial = ("budget_denied", BudgetExceeded("1日の費用上限に達しました"))
            if denial:
                record(conn, denial[0])
        if denial:
            raise denial[1]

        resp = provider.complete(system, prompt, model)
        price = self._price(provider, model) or 0.0
        cost = ((resp.input_tokens or 0) + (resp.output_tokens or 0)) / 1000 * price
        with self.store.tx() as conn:
            record(conn, "ok", resp, cost)
        return resp
