import shutil
import tempfile
import unittest
from pathlib import Path

from realoria_cc.config import Settings
from realoria_cc.core import System
from realoria_cc.db import Store

PW = "correct-horse-battery"


class FakeClock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


class SystemCase(unittest.TestCase):
    """一時データディレクトリ上に System を構築し、管理者・閲覧者・AI主体を用意する。"""

    settings_overrides: dict = {}

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rcc-test-"))
        self.clock = FakeClock()
        self.settings = Settings(data_dir=self.dir, lease_seconds=30, max_attempts=3,
                                 retry_backoff_seconds=1, **self.settings_overrides)
        self.system = self.make_system()
        s = self.system
        s.create_principal(None, "admin", "human", "管理者",
                           {"admin", "operator", "auditor", "viewer"}, 3, PW, bootstrap=True)
        self.admin = s.authenticate(s.login("admin", PW))
        s.create_principal(self.admin, "viewer", "human", "閲覧者", {"viewer"}, 1, PW)
        s.create_principal(self.admin, "op", "human", "運用者", {"operator", "viewer"}, 1, PW)
        s.create_principal(self.admin, "agent07", "ai", "AI機能07", {"agent"}, 1)
        self.viewer = s.authenticate(s.login("viewer", PW))
        self.op = s.authenticate(s.login("op", PW))
        self.agent = s.get_principal("agent07")

    def make_system(self) -> System:
        return System(self.settings, store=Store(self.settings.db_path, self.clock))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
