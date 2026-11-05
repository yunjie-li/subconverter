"""Verify deployed public/private isolation without printing subscription credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='https://sc.wwmm.date')
    parser.add_argument('--private-dir', required=True)
    args = parser.parse_args()
    directory = Path(args.private_dir)
    settings = json.loads((directory/'settings.json').read_text())
    base = args.base.rstrip('/')
    def request(path, key=None, body=None):
        headers = {'User-Agent': 'Mozilla/5.0 (WWMM verification)', 'Content-Type': 'application/json'}
        if key: headers['Authorization'] = 'Bearer ' + key
        req = Request(base + path, headers=headers, data=None if body is None else json.dumps(body).encode())
        try:
            response = urlopen(req, timeout=240)
        except HTTPError as error:
            response = error
        return response.code, response.read(), response.headers
    def check(label, condition):
        if not condition: raise RuntimeError(label + ' failed')
        print('PASS', label, flush=True)
    check('health', request('/healthz')[0] == 200)
    code, page, _ = request('/')
    check('public page', code == 200 and '我的预设'.encode() in page)
    for secret in [settings['admin_key'], *settings['tokens'].values(), settings.get('backend_token', '')]:
        if secret: check('no credentials in public page', secret.encode() not in page)
    check('preset requires key', request('/api/presets')[0] == 401)
    check('download key cannot read preset', request('/api/presets', settings['tokens']['loon'])[0] == 401)
    code, preset, _ = request('/api/presets', settings['admin_key'])
    check('six private pools', code == 200 and len(json.loads(preset)['pools']) == 6)
    for path in ['/render?path=private/loon-base.conf', '/getprofile?name=private/loon.ini', '/private/settings.json', '/get?url=/etc/passwd']:
        check('blocked internal endpoint', request(path)[0] == 404)
    check('private download requires key', request('/my/sub?target=loon')[0] == 401)
    check('private parameters cannot be replaced', request('/my/sub?' + urlencode({'target': 'loon', 'token': settings['tokens']['loon'], 'url': 'https://example.com'}))[0] == 400)
    check('client keys separated', request('/my/sub?' + urlencode({'target': 'clash', 'token': settings['tokens']['loon']}))[0] == 401)
    original = (directory/'loon-base.conf').read_text()
    cert = re.search(r'^ca-p12\s*=\s*(.+)$', original, re.I | re.M).group(1).strip()
    output = {}
    for target in ['loon', 'clash']:
        code, raw, headers = request('/my/sub?' + urlencode({'target': target, 'token': settings['tokens'][target]}))
        check('private ' + target + ' download', code == 200)
        check('private download not cached', 'no-store' in headers.get('Cache-Control', ''))
        text = raw.decode('utf-8-sig')
        output[target] = text
        if target == 'loon':
            check('same personal certificate', cert in text)
            check('plugins preserved', '[Plugin]' in text)
            check('scripts preserved', '[Script]' in text)
            check('Loon timeout uses milliseconds', 'max-timeout=5000' in text)
            check('Loon contains no GEOSITE', not re.search(r'^GEOSITE,', text, re.M))
        else:
            check('Clash has no Loon certificate', cert not in text and 'ca-p12' not in text.lower())
    synthetic = 'vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&security=tls&type=tcp&sni=example.com#Synthetic'
    code, public_loon, _ = request('/sub?' + urlencode({'target': 'loon', 'url': synthetic, 'list': 'false'}))
    check('ordinary users can convert', code == 200 and b'Synthetic' in public_loon)
    check('public Loon never includes personal certificate', cert.encode() not in public_loon and b'ca-p12' not in public_loon.lower())
    check('public local file access blocked', request('/sub?' + urlencode({'target': 'loon', 'url': '/base/private/loon.ini'}))[0] == 400)
    print('All checks passed. Device connectivity and third-party plugin behavior require client testing.', flush=True)


if __name__ == '__main__': main()
