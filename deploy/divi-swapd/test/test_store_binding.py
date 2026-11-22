"""Offline binding regression tests using disposable databases."""
import concurrent.futures
import contextlib
import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOL = Path(__file__).resolve().parents[1] / "store-binding.py"
spec = importlib.util.spec_from_file_location("binding", TOOL)
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


class BindingTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "swap.db"
        source = TOOL.parents[2] / "crates/divi-swap/src/store.rs"
        sql = source.read_text().split('const SCHEMA: &str = "', 1)[1].split('";', 1)[0]
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.executescript(sql)
            db.execute("pragma user_version=4")

    def invoke(self, *args):
        return subprocess.run([sys.executable, TOOL, args[0], self.path, *args[1:]],
                              capture_output=True, text=True)

    def bind(self, mode):
        return self.invoke("bind", "--mode", mode, "--attest-original-mode", mode)

    def test_race_and_immutable_binding(self):
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(self.bind, ("mock", "live")))
        self.assertEqual(sum(r.returncode == 0 for r in results), 1,
                         [(r.returncode, r.stderr) for r in results])
        for mode in ("mock", "live"):
            self.assertNotEqual(self.bind(mode).returncode, 0)
        self.assertEqual(self.invoke("inspect").returncode, 0)

    def test_failures_preserve_headers(self):
        before = self.path.read_bytes()
        for args in [("inspect", "--mode", "mock"), ("bind", "--mode", "live"),
                     ("bind", "--mode", "mock", "--attest-original-mode", "live")]:
            self.assertNotEqual(self.invoke(*args).returncode, 0)
        self.assertEqual(before, self.path.read_bytes())
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.execute("pragma user_version=6")
        before = self.path.read_bytes()
        self.assertNotEqual(self.bind("live").returncode, 0)
        self.assertEqual(before, self.path.read_bytes())

    def test_invalid_schema(self):
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.execute("ALTER TABLE docs RENAME TO missing_docs")
        before = self.path.read_bytes()
        self.assertNotEqual(self.bind("live").returncode, 0)
        self.assertEqual(before, self.path.read_bytes())

    def test_mock_record_refuses_live(self):
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.execute("INSERT INTO taker_swaps VALUES ('t', 0, ?)", ('{"usdc_admission":"Mock"}',))
            db.commit()
        before = self.path.read_bytes()
        self.assertNotEqual(self.bind("live").returncode, 0)
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(self.bind("mock").returncode, 0)

    def test_second_marker_write_failure_rolls_back(self):
        before = self.path.read_bytes()
        db = sqlite3.connect(self.path)
        def authorize(action, name, value, *_):
            if action == sqlite3.SQLITE_PRAGMA and name == "user_version" and value:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        db.set_authorizer(authorize)
        args = [str(TOOL), "bind", str(self.path), "--mode", "mock", "--attest-original-mode", "mock"]
        with patch.object(sys, "argv", args), patch.object(sqlite3, "connect", return_value=db):
            with self.assertRaises(sqlite3.DatabaseError):
                binding.main()
        self.assertEqual(before, self.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
