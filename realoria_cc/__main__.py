"""コマンドライン: python -m realoria_cc <command> --data <dir>

  init-admin   初期管理者 (人間) を作成
  add-user     利用者を追加 (管理者の資格情報が必要)
  serve        API + UI + 作業者 + 監視 を起動
  worker-once  キューから1件処理 (検証用)
  verify-audit 監査ログ検証 (終了コード 0=正常 3=異常)
  health       健康状態 (終了コード 0=正常 1=劣化 2=停止中 3=監査異常)
  backup       バックアップ作成
  restore      バックアップから復元 (サービス停止中に実行)
  demo-seed    模擬の参考資料を登録 (動作確認用)
"""
from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from .config import Settings
from .core import System
from .service import (EXIT_AUDIT_FAILED, EXIT_OK, Monitor, Worker, backup, health, restore)

DEFAULT_DATA = os.environ.get("REALORIA_CC_DATA", str(Path.home() / ".realoria_cc"))


def _password(prompt: str) -> str:
    env = os.environ.get("REALORIA_CC_PASSWORD")
    return env if env else getpass.getpass(prompt)


def _login(system: System, uid: str):
    token = system.login(uid, _password(f"{uid} のパスワード: "))
    return system.authenticate(token)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="realoria_cc")
    ap.add_argument("--data", default=DEFAULT_DATA, help="データディレクトリ")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("init-admin")
    a.add_argument("--id", required=True)
    a.add_argument("--name", required=True)
    u = sub.add_parser("add-user")
    u.add_argument("--admin", required=True)
    u.add_argument("--id", required=True)
    u.add_argument("--name", required=True)
    u.add_argument("--kind", choices=["human", "ai"], default="human")
    u.add_argument("--roles", required=True, help="カンマ区切り")
    u.add_argument("--clearance", type=int, default=1)
    s = sub.add_parser("serve")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    sub.add_parser("worker-once")
    sub.add_parser("verify-audit")
    sub.add_parser("health")
    b = sub.add_parser("backup")
    b.add_argument("--admin", required=True)
    r = sub.add_parser("restore")
    r.add_argument("--file", required=True)
    r.add_argument("--operator", required=True, help="実行者ID (監査記録用)")
    d = sub.add_parser("demo-seed")
    d.add_argument("--admin", required=True)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    data = Path(args.data)
    settings = System.init_data_dir(data)

    if args.cmd == "restore":
        print(json.dumps(restore(settings, Path(args.file), args.operator), ensure_ascii=False))
        print("復元しました。システムは停止状態です。確認後に管理者が再開してください。")
        return EXIT_OK

    system = System(settings)

    if args.cmd == "init-admin":
        pw = _password("初期管理者のパスワード (12文字以上): ")
        system.create_principal(None, args.id, "human", args.name,
                                {"admin", "operator", "auditor", "viewer"}, 3, pw, bootstrap=True)
        print("初期管理者を作成しました")
    elif args.cmd == "add-user":
        admin = _login(system, args.admin)
        roles = {x.strip() for x in args.roles.split(",") if x.strip()}
        pw = None
        if args.kind == "human":
            pw = getpass.getpass(f"{args.id} のパスワード (12文字以上): ")
        system.create_principal(admin, args.id, args.kind, args.name, roles, args.clearance, pw)
        print("作成しました")
    elif args.cmd == "serve":
        from .api import make_server
        workers = [Worker(system, f"w{i}") for i in range(settings.worker_count)]
        mon = Monitor(system)
        for t in workers + [mon]:
            t.start()
        srv = make_server(system, args.host, args.port)
        host, port = srv.server_address[:2]
        if host not in ("127.0.0.1", "::1", "localhost"):
            logging.warning("ローカル以外で待ち受けています: %s (TLS・アクセス制御を別途確認すること)", host)
        print(f"REALORIA (Claude Code版 PoC) http://{host}:{port}/")
        stop = threading.Event()

        def _shutdown(*_):
            stop.set()
            threading.Thread(target=srv.shutdown, daemon=True).start()
        signal.signal(signal.SIGINT, _shutdown)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _shutdown)
        try:
            srv.serve_forever()
        finally:
            for t in workers + [mon]:
                t.stop_evt.set()
            for t in workers + [mon]:
                t.join(timeout=10)
            system.anchor()
    elif args.cmd == "worker-once":
        print(Worker(system, "cli").run_once())
    elif args.cmd == "verify-audit":
        res = system.verify_audit(actor=None)
        print(json.dumps(res.as_dict(), ensure_ascii=False, indent=2))
        if res.ok:
            system.anchor()
        return EXIT_OK if res.ok else EXIT_AUDIT_FAILED
    elif args.cmd == "health":
        code, body = health(system)
        print(json.dumps(body, ensure_ascii=False, indent=2))
        return code
    elif args.cmd == "backup":
        print(backup(system, _login(system, args.admin)))
    elif args.cmd == "demo-seed":
        admin = _login(system, args.admin)
        from .demo import seed
        print(seed(system, admin))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
