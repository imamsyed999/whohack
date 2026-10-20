"""Compact a stopped checkout's whohack history; audit only unless --apply is set.

Preserves alerts, decisions, feedback, profiles, trust, file metadata and response
journals. Deletes old raw telemetry and exited-process history, not user files.
Uses bounded transactions to avoid creating another multi-gigabyte WAL file.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import sqlite3
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
MAX_EVENTS = 100_000
MAX_EXITED = 10_000
PROTECTED = ('files', 'profiles', 'alerts', 'decisions', 'feedback', 'allowlist',
             'settings', 'profile_observations', 'destination_history')


@contextmanager
def stopped_service(data):
    import msvcrt
    with (data / 'service.lock').open('a+b') as lock:
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise RuntimeError('Stop this whohack instance before compacting history') from error
        try:
            yield
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def protected_records(con):
    return {table: {'columns': [r[1] for r in con.execute('PRAGMA table_info(' + table + ')')],
                    'rows': con.execute('SELECT * FROM ' + table + ' ORDER BY rowid').fetchall()}
            for table in PROTECTED}


def counts(con):
    return {table: con.execute('SELECT count(*) FROM ' + table).fetchone()[0]
            for table in ('events', 'connections', 'dns', 'processes', 'alerts', 'feedback')}


def compact(con, cutoff):
    event_boundary = con.execute(
        'SELECT ts,id FROM events ORDER BY ts DESC,id DESC LIMIT 1 OFFSET ?',
        (MAX_EVENTS - 1,)).fetchone()
    event_predicate, event_args = 'ts < ?', [cutoff]
    if event_boundary:
        event_predicate += ' OR (ts,id) < (?,?)'
        event_args += list(event_boundary)
    process_boundary = con.execute(
        'SELECT exit_time,id FROM processes WHERE exit_time IS NOT NULL '
        'ORDER BY exit_time DESC,id DESC LIMIT 1 OFFSET ?', (MAX_EXITED - 1,)).fetchone()
    process_predicate, process_args = 'exit_time < ?', [cutoff]
    if process_boundary:
        process_predicate += ' OR (exit_time,id) < (?,?)'
        process_args += list(process_boundary)
    for table, predicate, args in (('events', event_predicate, event_args),
                                   ('processes', process_predicate, process_args)):
        deleted = 0
        while True:
            with con:
                n = con.execute('DELETE FROM ' + table + ' WHERE id IN (SELECT id FROM '
                                + table + ' WHERE ' + predicate + ' LIMIT 10000)', args).rowcount
            checkpoint = con.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            if checkpoint[0]:
                raise RuntimeError('Database is in use; compaction stopped')
            deleted += n
            if n == 0:
                break
        print(f'Pruned {deleted} {table} records', flush=True)
    con.execute('PRAGMA auto_vacuum=INCREMENTAL')
    con.execute('VACUUM')
    con.execute('PRAGMA wal_checkpoint(TRUNCATE)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / '.vigil/windows/config.toml')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'win32':
        parser.error('Run on Windows, alongside the native service')
    config = args.config.resolve(strict=True)
    cfg = tomllib.loads(config.read_text(encoding='utf-8-sig'))
    data = (config.parent / cfg['paths']['data_dir']).resolve(strict=True)
    db = (data / cfg.get('storage', {}).get('db_file', 'vigil.db')).resolve(strict=True)
    if not config.is_relative_to(ROOT) or not data.is_relative_to(ROOT) or db.parent != data:
        parser.error('This maintenance tool only handles a database inside this checkout')
    days = cfg.get('storage', {}).get('event_retention_days', 30)
    if not isinstance(days, int) or not 1 <= days <= 3650:
        parser.error('Invalid event retention')
    with stopped_service(data):
        con = sqlite3.connect(db.as_uri() + '?mode=rw', uri=True)
        try:
            con.execute('PRAGMA foreign_keys=ON')
            if con.execute('PRAGMA user_version').fetchone()[0] != 6:
                raise RuntimeError('Unsupported schema; review maintenance tool first')
            report = {'utc': datetime.now(timezone.utc).isoformat(), 'applied': args.apply,
                      'before_bytes': db.stat().st_size, 'before': counts(con)}
            if args.apply:
                evidence = protected_records(con)
                stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                output = ROOT / '.vigil/checks/storage'
                output.mkdir(parents=True, exist_ok=True)
                backup = output / (stamp + '-protected-records.json.gz')
                with gzip.open(backup, 'xt', encoding='utf-8') as handle:
                    json.dump(evidence, handle)
                response = data / 'responses.json'
                response_before = response.read_bytes() if response.exists() else None
                compact(con, int(time.time() * 1000) - days * 86400000)
                if protected_records(con) != evidence:
                    raise RuntimeError('Protected evidence changed; inspect the saved backup')
                if (response.read_bytes() if response.exists() else None) != response_before:
                    raise RuntimeError('Response journal changed during maintenance')
                if con.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise RuntimeError('Database integrity check failed')
                if con.execute('PRAGMA foreign_key_check').fetchall():
                    raise RuntimeError('Database foreign key check failed')
                report.update(after_bytes=db.stat().st_size, after=counts(con),
                              evidence_unchanged=True, response_journal_unchanged=True,
                              incremental_vacuum=con.execute('PRAGMA auto_vacuum').fetchone()[0] == 2,
                              evidence_backup=str(backup.relative_to(ROOT)))
                (output / (stamp + '-compaction.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
            print(json.dumps(report, indent=2))
        finally:
            con.close()


if __name__ == '__main__':
    main()
