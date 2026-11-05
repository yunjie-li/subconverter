"""Apply the shared multiplier filter to source subscriptions after a private backup."""
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
    operation = json.loads(Path(__file__).with_name('multiplier-filter.json').read_text())
    def api(path, method='GET', data=None):
        req = Request(base + path, method=method,
                      data=None if data is None else json.dumps(data, ensure_ascii=False).encode(),
                      headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'})
        with urlopen(req, timeout=60) as response: result = json.load(response)
        if result.get('status') != 'success': raise RuntimeError('Sub-Store API rejected operation')
        return result['data']
    subs, collections = api('/api/subs'), api('/api/collections')
    directory = Path(args.backup_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = directory / ('multiplier-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.json')
    fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as file: json.dump({'subscriptions': subs, 'collections': collections}, file, ensure_ascii=False)
    for sub in subs:
        process = [item for item in sub.get('process', []) if item.get('customName') != operation['customName']]
        process.append(operation)
        if args.apply:
            path = '/api/sub/' + quote(sub['name'], safe='')
            api(path, 'PATCH', {'process': process})
            if api(path)['process'] != process: raise RuntimeError('Filter read-back differs')
        print('Filtered source:' if args.apply else 'Would filter source:', sub['name'])


if __name__ == '__main__': main()
