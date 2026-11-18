"""動作確認用の模擬資料。REALORIA の正式情報源ではない (status='reference' / 内容は架空)。"""
from __future__ import annotations

from .config import INTERNAL, PUBLIC, RESTRICTED

DEMO_SOURCES = [
    ("demo-editorial-policy", "【模擬】編集方針メモ", "demo-1", PUBLIC,
     "これは動作確認用の架空資料です。インタビューは本人確認済みの発言のみを掲載する。"
     "掲載前に事実確認を二重に行う。"),
    ("demo-reader-survey", "【模擬】読者アンケート集計", "demo-1", INTERNAL,
     "これは動作確認用の架空資料です。回答者の多くが長文記事の読了に満足と回答した。"
     "スマートフォンからの閲覧が多い。"),
    ("demo-raw-interview", "【模擬】未公開取材メモ", "demo-1", RESTRICTED,
     "これは動作確認用の架空資料です。未公開の取材素材は外部AIへ送信してはならない区分の例。"),
]


def seed(system, admin) -> list[str]:
    done = []
    existing = {s["id"] for s in system.list_sources(admin)}
    for sid, title, ver, cls, content in DEMO_SOURCES:
        if sid in existing:
            continue
        system.register_source(admin, sid, title, ver, "reference", cls, content)
        done.append(sid)
    return done
