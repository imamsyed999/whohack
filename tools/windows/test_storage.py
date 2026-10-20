"""Small native-schema tests for offline history compaction (no model or downloads)."""

import contextlib
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import compact_history as history
from launch import binary


class StorageTests(unittest.TestCase):
    def setUp(self):
        parent = history.ROOT / '.vigil/checks/storage'
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='fixture-', dir=parent)
        self.root = Path(self.temp.name)
        assert self.root.resolve().is_relative_to(parent.resolve())
        self.addCleanup(self.temp.cleanup)
        self.config = self.root / 'config.toml'
        self.config.write_text('[paths]\ndata_dir="data"\nlog_dir="logs"\nrules_dir="rules"\n', encoding='utf-8')
        subprocess.run([str(binary('whohack-service')), '--config', str(self.config), '--init-db'],
                       check=True, capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        self.db = self.root / 'data/vigil.db'

    def test_compaction_preserves_evidence_and_live_identity(self):
        with contextlib.closing(sqlite3.connect(self.db)) as con, con:
            now = int(time.time() * 1000)
            for seq, ts in enumerate([40, 10, 30, 40, 20, 40], 1):
                con.execute("INSERT INTO events (id,ts,pid,kind,data) VALUES (?,?,7,'dns_query','{}')", (seq, now + ts))
                con.execute("INSERT INTO dns (event_id,ts,pid,name) VALUES (?,?,7,'fixture.example')", (seq, now + ts))
            for pid, exit_time in [(1, now + 10), (2, None), (3, now + 30), (4, now + 20)]:
                con.execute("INSERT INTO processes (pid,ppid,start_time,exit_time,exe_sha256,exe_path,path_class,tainted,app_id) "
                            "VALUES (?,0,1,?,'fixture','fixture','other',0,'fixture')", (pid, exit_time))
            con.execute("INSERT INTO alerts (id,ts,pid,app_id,label,p_benign,p_suspicious,p_malicious,tactic,severity,action,tier,reasons) "
                        "VALUES (1,1,7,'fixture','suspicious',0,1,0,'none',2,'ask_user',0,'[\"saved evidence\"]')")
            con.execute("INSERT INTO feedback (alert_id,ts,user_action,note) VALUES (1,2,'allow','human reviewed')")
            before = history.protected_records(con)
        journal = self.root / 'data/responses.json'
        journal.write_text('[]', encoding='utf-8')
        captured = io.StringIO()
        with patch.object(sys, 'argv', ['compact_history.py', '--config', str(self.config), '--apply']), \
                patch.object(history, 'MAX_EVENTS', 2), patch.object(history, 'MAX_EXITED', 1), \
                contextlib.redirect_stdout(captured):
            history.main()
        with contextlib.closing(sqlite3.connect(self.db)) as con:
            self.assertEqual(history.protected_records(con), before)
            self.assertEqual(con.execute('SELECT id FROM events ORDER BY id').fetchall(), [(4,), (6,)])
            self.assertEqual(con.execute('SELECT count(*) FROM dns').fetchone(), (2,))
            self.assertEqual(con.execute('SELECT pid FROM processes ORDER BY pid').fetchall(), [(2,), (3,)])
            self.assertEqual(con.execute('PRAGMA auto_vacuum').fetchone(), (2,))
        self.assertEqual(journal.read_text(), '[]')
        # Remove only the small evidence/report files this particular test created.
        report = json.loads(captured.getvalue()[captured.getvalue().index('{'):])
        backup = history.ROOT / report['evidence_backup']
        backup.unlink()
        backup.with_name(backup.name.replace('-protected-records.json.gz', '-compaction.json')).unlink()

    def test_busy_service_lock_refuses_maintenance(self):
        import msvcrt
        data = self.root / 'data'
        with (data / 'service.lock').open('a+b') as lock:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            try:
                result = subprocess.run([sys.executable, str(Path(history.__file__)), '--config', str(self.config), '--apply'],
                                        capture_output=True, text=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Stop this whohack instance', result.stderr)
            finally:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


if __name__ == '__main__':
    unittest.main()
