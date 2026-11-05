import importlib.util
import base64
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.parse import urlencode

spec = importlib.util.spec_from_file_location('gateway', Path(__file__).with_name('gateway.py'))
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = {'admin_key': 'admin-example-key-' * 3,
                       'backend_token': 'backend-internal-key-' * 3,
                       'tokens': {'loon': 'loon-example-key-' * 3, 'clash': 'clash-example-key-' * 3, 'egern': 'egern-example-key-' * 3},
                       'pools': ['WM 均衡', '日常主用', 'AI 优先', 'AI 后备', '最后备用', 'Cathy 专用']}
        p = Path(self.temp.name) / 'settings.json'
        p.write_text(json.dumps(self.config))
        gateway.SETTINGS_FILE = p
        gateway.EGERN_FILE = Path(self.temp.name) / 'egern-base.yaml'
        gateway.EGERN_FILE.write_text((Path(__file__).with_name('egern-base.yaml')).read_text())
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

    def test_preset_key_rotation_preserves_long_download_keys(self):
        previous = self.config['admin_key']
        chosen = 'Example#2026!'
        self.config['admin_key'] = chosen
        gateway.SETTINGS_FILE.write_text(json.dumps(self.config))
        self.assertEqual(self.request('/api/presets', key=chosen)[0], 200)
        self.assertEqual(self.request('/api/presets', key=previous)[0], 401)
        self.assertEqual(self.request('/my/sub?target=loon&token=' + self.config['tokens']['loon'])[0], 200)
        self.config['admin_key'] = 'x' * 11
        gateway.SETTINGS_FILE.write_text(json.dumps(self.config))
        with self.assertRaises(ValueError): gateway.settings()
        self.config['admin_key'] = chosen
        self.config['tokens']['loon'] = 'x' * 31
        gateway.SETTINGS_FILE.write_text(json.dumps(self.config))
        with self.assertRaises(ValueError): gateway.settings()

    def test_public_routes_cannot_read_private_or_local_files(self):
        for path in ['/render?path=private/loon-base.conf', '/getprofile?name=private/loon.ini', '/private/settings.json', '/get?url=/etc/passwd', '/api/settings']:
            self.assertEqual(self.request(path)[0], 404)
        for query in ['url=/base/private/loon.ini', 'url=https://example.com&config=/base/private/loon-base.conf', 'url=https://example.com&token=secret', 'url=https://example.com&upload=true']:
            self.assertEqual(self.request('/sub?target=loon&' + query)[0], 400)
        self.assertFalse(self.calls)
        self.assertEqual(self.request('/sub?target=loon&url=https://example.com/sub')[0], 200)
        self.assertFalse(self.calls[-1][1])

    def test_loon_rules_are_wrapped_and_unsupported_types_filtered(self):
        body = b'[Remote Rule]\nhttps://example.com/rules.list,Daily\n[MITM]\nca-p12 = synthetic-certificate\n'
        adapted = gateway.adapt_loon(body)
        self.assertIn(b'/getruleset?type=1&url=', adapted)
        self.assertIn(b'ca-p12 = synthetic-certificate', adapted)
        self.assertEqual(gateway.adapt_loon(adapted), adapted)
        rules = b'DOMAIN-SUFFIX,example.com\nDOMAIN-REGEX,^example\\.com$\nIP-CIDR6,2001:db8::/32\nURL-REGEX,^https://example.com/\n'
        filtered = gateway.compatible_rules(rules)
        self.assertNotIn(b'DOMAIN-REGEX', filtered)
        self.assertIn(b'DOMAIN-SUFFIX,example.com', filtered)
        self.assertIn(b'IP-CIDR6', filtered)

    def test_large_compatible_cn_rules_redirect_without_relaying(self):
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs): return None
        source = next(iter(gateway.DIRECT_SURGE_RULES))
        encoded = base64.urlsafe_b64encode(('clash-classic:' + source).encode()).decode().rstrip('=')
        url = self.base + '/getruleset?' + urlencode({'type': '1', 'url': encoded})
        with self.assertRaises(HTTPError) as result:
            build_opener(NoRedirect()).open(url)
        self.assertEqual(result.exception.code, 302)
        self.assertEqual(result.exception.headers['Location'], source)
        result.exception.close()
        self.assertFalse(self.calls)
        self.assertEqual(self.request('/getruleset?' + urlencode({'type': '6', 'url': encoded}))[0], 200)
        self.assertTrue(self.calls)


    def egern_intermediate(self, path, private=False):
        self.calls.append((path, private))
        return b'proxies:\n  - {name: "[AI] synthetic", type: vless, server: example.com, port: 443, uuid: id, tls: true}\nproxy-groups:\n  - {name: Group, type: select, proxies: ["[AI] synthetic"]}\nrules: ["MATCH,Group"]\n', {}

    def test_egern_public_and_private_generation_share_clash_ini(self):
        gateway.convert = self.egern_intermediate
        code, raw, _ = self.request('/sub?target=egern&url=https://example.com/sub&emoji=true')
        self.assertEqual(code, 200)
        self.assertIn(b'policy_groups:', raw)
        self.assertIn('target=egern', gateway.egern.load(raw)['auto_update']['url'])
        self.assertIn('target=clash', self.calls[-1][0])
        self.assertIn('emoji=true', self.calls[-1][0])
        self.assertFalse(self.calls[-1][1])
        token = self.config['tokens']['egern']
        self.assertEqual(self.request('/my/sub?target=egern&token=' + self.config['tokens']['loon'])[0], 401)
        self.assertEqual(self.request('/my/sub?target=egern&token=' + token + '&url=https://example.com')[0], 400)
        code, raw, headers = self.request('/my/sub?target=egern&token=' + token)
        self.assertEqual(code, 200)
        self.assertIn('private%2Fclash.ini', self.calls[-1][0])
        self.assertTrue(self.calls[-1][1])
        profile = gateway.egern.load(raw)
        self.assertIn('target=egern', profile['auto_update']['url'])
        self.assertNotIn(self.config['backend_token'].encode(), raw)
        self.assertIn('no-store', headers['Cache-Control'])
        code, raw, _ = self.request('/api/generate', 'POST', {'target': 'egern'}, self.config['admin_key'])
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)['pool_counts'], {'AI': 1})

    def test_egern_template_editor_requires_admin_and_preserves_invalid_input(self):
        self.assertEqual(self.request('/api/egern-settings')[0], 401)
        self.assertEqual(self.request('/api/egern-settings', key=self.config['tokens']['egern'])[0], 401)
        key = self.config['admin_key']
        code, raw, _ = self.request('/api/egern-settings', key=key)
        self.assertEqual(code, 200)
        original = gateway.EGERN_FILE.read_bytes()
        for value in ['proxies: []', 'rules: []', '_wwmm: {priorities: {MESL: -1}}', 'invalid: [', '!!python/object/apply:os.system [echo no]']:
            self.assertEqual(self.request('/api/egern-settings', 'POST', {'yaml': value}, key)[0], 400)
            self.assertEqual(gateway.EGERN_FILE.read_bytes(), original)
        value = 'ipv6: true\nmodules: []\n_wwmm:\n  priorities: {MESL: 0.8}\n'
        self.assertEqual(self.request('/api/egern-settings', 'POST', {'yaml': value}, key)[0], 200)
        self.assertEqual(gateway.EGERN_FILE.read_text(), value)
        self.assertEqual(gateway.EGERN_FILE.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.request('/egern/base.yaml')[0], 404)

    def test_egern_remote_rules_use_public_converter_and_block_local_paths(self):
        encoded = lambda text: base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')
        for source in ['surge:file:///etc/passwd', 'surge:http://127.0.0.1/private', 'clash-classic:http://private-converter:25500/config']:
            self.assertEqual(self.request('/egern/rules?' + urlencode({'url': encoded(source)}))[0], 400)
        self.assertFalse(self.calls)
        def convert(path, private=False):
            self.calls.append((path, private))
            return b'payload:\n - DOMAIN-SUFFIX,example.com\n - DOMAIN-REGEX,^ad\n - IP-CIDR,10.0.0.0/8,no-resolve\n', {}
        gateway.convert = convert
        code, raw, _ = self.request('/egern/rules?' + urlencode({'url': encoded('surge:https://example.com/rules.list')}))
        self.assertEqual(code, 200)
        self.assertIn(b'domain_suffix_set:', raw)
        self.assertIn(b'domain_regex_set:', raw)
        self.assertIn('type=6', self.calls[-1][0])
        self.assertFalse(self.calls[-1][1])


if __name__ == '__main__': unittest.main()
