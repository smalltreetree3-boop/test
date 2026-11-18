# REALORIA 全組織AIエージェントシステム — Claude Code 独立実装（PoC）

REALORIA の6本部・33基幹機能を支えるAIエージェント基盤の試作です。OpenAI Codex 版とは独立に設計・実装しており、ファイルやDBは共有していません（パッケージ名 `realoria_cc`）。

> **現在の状態**: 試作です。模擬AIのみで動作します。実LLMへの接続、Windows実機での検証、本番運用はいずれも未実施です。
> REALORIAの正式情報源が未提供のため、33機能の名称・権限・承認条件は「未照合」とし、承認機能は無効化しています。

## 文書

| 文書 | 内容 |
|---|---|
| [docs/REVIEW_REPORT.md](docs/REVIEW_REPORT.md) | **審議資料**: 実装済み・未実装、テスト結果、セキュリティ評価、Codex版との比較観点、残存リスク、次工程 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 全体アーキテクチャ、不変条件、技術選定 |
| [docs/INTERFACES.md](docs/INTERFACES.md) | 統合用インターフェース仕様（API・出力契約・Provider IF） |
| [docs/screenshots/](docs/screenshots/) | UIの画面（PC・スマホ） |

## 動作環境

- Python 3.11 以上（検証環境は Linux / Python 3.13）。**追加パッケージは不要**です（標準ライブラリのみ）
- 最新の Chrome / Edge（画面確認は Chromium のみで実施）

## 起動手順

```bash
# 1) データディレクトリを決める（既定は ~/.realoria_cc）。DBと鍵はここに作られます
#    Windows (PowerShell) の例: $env:REALORIA_CC_DATA="C:\realoria_cc_data"
export REALORIA_CC_DATA=./local-data

# 2) 初期管理者（人間）を作成。パスワードは12文字以上で、対話入力します
python -m realoria_cc init-admin --id admin --name 運営責任者

# 3) （任意）動作確認用の模擬資料を登録。内容は架空です
python -m realoria_cc demo-seed --admin admin

# 4) 起動（API + UI + 作業者 + 監視）
python -m realoria_cc serve
#   → http://127.0.0.1:8765/ をブラウザで開く
```

利用者の追加（ロール: viewer / operator / auditor / admin / approver、AI主体は agent）:

```bash
python -m realoria_cc add-user --admin admin --id editor1 --name 編集担当 --roles operator,viewer --clearance 1
```

運用コマンド:

```bash
python -m realoria_cc health          # 終了コード 0正常 1劣化 2停止中 3監査異常
python -m realoria_cc verify-audit    # 監査ログの検証
python -m realoria_cc backup --admin admin
python -m realoria_cc restore --file <backup.db> --operator admin   # serve を止めてから実行
```

テスト:

```bash
python -m unittest discover -s tests -t .
```

### Windows で常駐させる場合（未検証の手順案）

- NSSM などで `python -m realoria_cc serve` をサービスとして登録し、異常終了時に自動再起動させます
- タスクスケジューラで `health` を5分ごとに実行し、終了コードが0以外なら通知します（通知の方法は運用側で決めます）
- データディレクトリの `secrets\` は、NTFS のアクセス権でサービス実行アカウントだけが読めるようにします

## 設定（`<データディレクトリ>/settings.json`、すべて任意）

既定値はすべて安全側に寄せてあります。主な項目:

| キー | 既定値 | 説明 |
|---|---|---|
| `host` / `port` | `127.0.0.1` / `8765` | ローカル以外で待ち受ける場合は TLS とアクセス制御が別途必要です |
| `external_ai_enabled` | `false` | 外部AIへの送信。有効にするには承認が必要です |
| `max_external_classification` | `0`（公開） | 外部へ送信してよい最大区分。区分3（厳秘）は設定に関係なく送信しません |
| `daily_call_limit` / `daily_cost_limit_usd` | `200` / `0.0` | 日次の上限 |
| `model_prices` | `{}` | `"provider:model": USD/1Kトークン`。単価が未設定の外部モデルは拒否します |
| `voice_input_enabled` | `false` | ブラウザの音声入力。音声がクラウドへ送られる可能性があるため既定で無効です |
| `lease_seconds` / `max_attempts` | `60` / `3` | ジョブのリース期間と再試行回数 |

## 安全条件（現段階）

- 外部API接続、有料サービス、本番環境の操作、自動公開、承認・契約・支払の実行は、いずれも実装していません
- 監査で異常を検知すると自動的に停止します。再開できるのは、人間の管理者が監査検証に成功した場合だけです
- Google Drive は参照していません
