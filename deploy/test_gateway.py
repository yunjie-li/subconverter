import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location('gateway', Path(__file__).with_name('gateway.py'))
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = {'admin_key': 'admin-example-key-' * 3,
                       'backend_token': 'backend-internal-key-' * 3,
                       'tokens': {'loon': 'loon-example-key-' * 3, 'clash': 'clash-example-key-' * 3},
                       'pools': ['WM 均衡', '日常主用', 'AI 优先', 'AI 后备', '最后备用', 'Cathy 专用']}
        p = Path(self.temp.name) / 'settings.json'
        p.write_text(json.dumps(self.config))
        gateway.SETTINGS_FILE = p
        self.server = gateway.Server(('127.0.0.1', 0), gateway.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = 'http://127.0.0.1:' + str(self.server.server_port)
        self.previous = gateway.convert
        self.calls = []
        def convert(path, private=False):
            self.calls.append((path, private))
            return b'[Proxy]\nsynthetic = VLESS,example.com,443,"id",transport=tcp\n[Proxy Group]\nDaily = select,synthetic\n[Rule]\nFINAL,Daily\n', {}
        gateway.convert = convert

    def tearDown(self):
        gateway.convert = self.previous
        self.server.shutdown()
        self.server.server_close()
        self.temp.cleanup()

    def request(self, path, method='GET', data=None, key=None):
        headers = {'Content-Type': 'application/json'}
        if key: headers['Authorization'] = 'Bearer ' + key
        try:
            r = urlopen(Request(self.base + path, data=None if data is None else json.dumps(data).encode(), headers=headers, method=method))
        except HTTPError as error:
            r = error
        return r.code, r.read(), r.headers

    def test_private_requires_token_and_blocks_overrides(self):
        self.assertEqual(self.request('/my/sub?target=loon')[0], 401)
        self.assertEqual(self.request('/my/sub?target=loon&token=wrong')[0], 401)
        token = self.config['tokens']['loon']
        self.assertEqual(self.request('/my/sub?target=loon&token=' + token + '&url=https://example.com')[0], 400)
        self.assertEqual(self.request('/my/sub?target=loon&target=clash&token=' + token)[0], 400)
        self.assertEqual(self.request('/my/sub?target=clash&token=' + token)[0], 401)
        self.assertFalse(self.calls)
        code, raw, headers = self.request('/my/sub?target=loon&token=' + token)
        self.assertEqual(code, 200)
        self.assertTrue(self.calls[-1][1])
        self.assertIn(self.config['backend_token'], self.calls[-1][0])
        self.assertNotIn(token, self.calls[-1][0])
        self.assertIn('no-store', headers['Cache-Control'])

    def test_private_preset_auth_and_read_only_download_token(self):
        self.assertEqual(self.request('/api/presets')[0], 401)
        self.assertEqual(self.request('/api/presets', key=self.config['tokens']['loon'])[0], 401)
        code, raw, _ = self.request('/api/presets', key=self.config['admin_key'])
        self.assertEqual(code, 200)
        self.assertEqual(len(json.loads(raw)['pools']), 6)
        self.assertNotIn(self.config['admin_key'].encode(), raw)
        self.assertNotIn(self.config['backend_token'].encode(), raw)
        code, _, _ = self.request('/api/generate', 'POST', {'target': 'loon'}, self.config['admin_key'])
        self.assertEqual(code, 200)
        self.assertTrue(self.calls[-1][1])

    def test_public_routes_cannot_read_private_or_local_files(self):
        for path in ['/render?path=private/loon-base.conf', '/getprofile?name=private/loon.ini', '/private/settings.json', '/get?url=/etc/passwd', '/api/settings']:
            self.assertEqual(self.request(path)[0], 404)
        for query in ['url=/base/private/loon.ini', 'url=https://example.com&config=/base/private/loon-base.conf', 'url=https://example.com&token=secret', 'url=https://example.com&upload=true']:
            self.assertEqual(self.request('/sub?target=loon&' + query)[0], 400)
        self.assertFalse(self.calls)
        self.assertEqual(self.request('/sub?target=loon&url=https://example.com/sub')[0], 200)
        self.assertFalse(self.calls[-1][1])


if __name__ == '__main__': unittest.main()
