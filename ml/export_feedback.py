"""Export local feedback for human labeling; never assume Allow means benign."""
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from dataset import write_jsonl


def export(database, limit=10000):
    connection = sqlite3.connect(Path(database).resolve(strict=True).as_uri() + '?mode=ro', uri=True)
    try:
        query = '''SELECT f.id, f.ts, f.user_action, d.state_text, d.model_name, d.model_revision,
                          a.target FROM feedback f JOIN alerts a ON a.id=f.alert_id
                   JOIN decisions d ON d.id=(SELECT MAX(id) FROM decisions WHERE alert_id=a.id)
                   ORDER BY f.id DESC LIMIT ?'''
        for identity, ts, action, state, model, revision, target in connection.execute(query, (limit,)):
            if not target:
                continue
            process = json.loads(target); file = process.get('script') or process['exe']
            yield dict(schema_version=1, id=hashlib.sha256(f'{file["sha256"]}:{identity}:{ts}'.encode()).hexdigest(),
                       ts=ts, app_sha256=file['sha256'], state=state, user_action=action,
                       model=model, revision=revision, labels=None, review={'accepted': False})
    finally:
        connection.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--limit', type=int, default=10000)
    a = p.parse_args()
    if not 1 <= a.limit <= 100000:
        p.error('limit must be 1..100000')
    write_jsonl(a.output, export(a.database, a.limit))
    print(f'Wrote review candidates to {a.output}; no files uploaded and no gold labels inferred.')


if __name__ == '__main__':
    main()
