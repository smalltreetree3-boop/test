# 統合用インターフェース仕様（Claude Code版 v0.1.0-poc）

Codex版との比較や統合のために、外部から見える契約をまとめます。内部実装は変更される可能性があります。

## 1. HTTP API

共通事項:
- 認証は `Authorization: Bearer <token>`。Cookie は使いません。
- 本文は `application/json` のみ受け付けます（それ以外は 415）。上限は 256KiB（超えると 413）。
- エラー形式は `{"error": "日本語メッセージ"}`。401=未認証、403=権限不足またはポリシー違反、404、409=状態の競合または緊急停止中、400=入力不正。

| メソッド | パス | 必要な権限 | 説明 |
|---|---|---|---|
| GET | `/api/health` | 不要 | `{ok, code, halted}` のみを返します（内部情報は出しません） |
| POST | `/api/login` | 不要 | `{id, password}` → `{token}`。5回失敗すると15分ロックします |
| POST | `/api/logout` | 認証済み | セッションを失効させます |
| GET | `/api/me` | 認証済み | 主体の情報 |
| GET | `/api/overview` | org.read | 状態・組織レジストリ・機能別の活動・最新ジョブ・プロバイダ |
| GET | `/api/providers` | 認証済み | プロバイダ一覧と有効/無効の理由 |
| GET/POST | `/api/jobs` | job.read / job.submit | 一覧 / 受付（下記） |
| GET | `/api/jobs/{id}` | job.read + 区分 | 詳細、提案、AIへの送信記録 |
| POST | `/api/jobs/{id}/pause\|resume\|cancel` | job.control | `{reason}` |
| POST | `/api/jobs/{id}/release` | job.release_hold（人間のみ） | Hold を解除し、1試行だけ許可します |
| POST | `/api/jobs/{id}/model` | job.change_model（人間のみ） | queued/paused のジョブのみ変更できます |
| POST | `/api/system/stop` | system.emergency_stop | `{reason}` |
| POST | `/api/system/resume` | system.resume（人間の admin） | 監査検証が成功していることが条件です |
| GET | `/api/audit?after=N` | audit.read | 監査ログ（最大500件） |
| POST | `/api/audit/verify` | audit.verify | 検証結果 |
| GET/POST | `/api/sources` | source.read / source.register（人間のみ） | `status=official` の登録は現在拒否されます |
| POST | `/api/approvals/{id}` | approval.decide（人間のみ） | **常に 403**（正式権限が未照合のため） |

ジョブ受付 `POST /api/jobs`:
```json
{"function_id": "07", "instruction": "…", "source_ids": ["demo-reader-survey"],
 "classification": 1, "provider": "mock", "model": "mock-analyst-1",
 "output_kind": "analysis", "idempotency_key": "任意の一意キー"}
```

## 2. モデル出力の契約（エージェント → システム）

```json
{"summary": "…",
 "findings":  [{"text": "…", "source_ids": ["資料ID"]}],
 "unknowns":  ["確認できません: …"],
 "proposals": [{"text": "…", "source_ids": ["資料ID"]}]}
```
`findings` と `proposals` の各要素には、提供した資料のIDを1つ以上付ける必要があります。付いていない場合は `needs_review` になります。

## 3. Provider インターフェース（Python）

```python
class Provider:
    name: str; label: str
    locality: "mock" | "local" | "external"
    models: tuple[str, ...]
    implemented: bool
    def complete(self, system: str, prompt: str, model: str) -> ModelResponse: ...
```
新しいプロバイダは `providers.PROVIDERS` に登録します。送信の可否、上限、記録は `ModelRouter.call` が一元的に扱うため、プロバイダ側では判断しません。

## 4. 組織レジストリ（`realoria_cc/data/org_registry.json`）

正式情報源を照合したら、このファイルを版を上げて差し替えます。読込時に SHA-256 を監査ログへ記録します。`OrgRegistry.validate()` は次の場合に読込を拒否します。
- 機能が 01〜33 の連番でない、または本部の範囲に重複・欠落がある
- 23〜25 が Signal 限定になっていない
- 未照合の機能に `approval_authority` が設定されている

## 5. 終了コード（CLI）

| コード | 意味 |
|---|---|
| 0 | 正常 |
| 1 | 劣化（DB異常、または作業者のハートビートが60秒以上途絶） |
| 2 | 緊急停止中 |
| 3 | 監査異常 |
