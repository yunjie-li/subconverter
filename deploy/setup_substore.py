"""Create missing purpose collections, preserving existing subscriptions/collections.

SUBSTORE_ACCESS_FILE points to a private JSON file with substore_base.
The full pre-change snapshot is saved outside the repository before any mutation.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup-dir', required=True)
    args = parser.parse_args()
    base = json.loads(Path(os.environ['SUBSTORE_ACCESS_FILE']).read_text())['substore_base'].rstrip('/')
    def api(path, method='GET', data=None):
        request = Request(base + path, method=method, data=None if data is None else json.dumps(data, ensure_ascii=False).encode(),
                          headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json', 'Content-Type': 'application/json'})
        with urlopen(request, timeout=60) as response: result = json.load(response)
        if result.get('status') != 'success': raise RuntimeError('Sub-Store API rejected the operation')
        return result['data']
    subscriptions, collections = api('/api/subs'), api('/api/collections')
    snapshot = Path(args.backup_dir)
    snapshot.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = snapshot / ('substore-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.json')
    fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as handle: json.dump({'subscriptions': subscriptions, 'collections': collections}, handle, ensure_ascii=False)
    existing = {item['name'] for item in collections}
    available = {item['name'] for item in subscriptions}
    pools = json.loads(Path(__file__).with_name('substore-pools.json').read_text())
    for pool in pools:
        if set(pool['subscriptions']) - available: raise RuntimeError('A required source subscription is missing: ' + pool['displayName'])
        if pool['name'] in existing:
            print('Preserved existing pool:', pool['displayName'])
            continue
        if args.apply:
            api('/api/collections', 'POST', pool)
            saved = api('/api/collection/' + quote(pool['name']))
            if saved['process'] != pool['process']: raise RuntimeError('Pool read-back differs')
        print('Created' if args.apply else 'Would create', pool['displayName'])


if __name__ == '__main__': main()
