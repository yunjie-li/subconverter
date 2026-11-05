import unittest
import egern


class EgernTests(unittest.TestCase):
    def node(self, kind, **fields):
        return {'name': kind, 'type': kind, 'server': 'example.com', 'port': 443, **fields}

    def test_reality_vision_and_websocket_are_preserved(self):
        raw = self.node('vless', uuid='synthetic-id', tls=True, flow='xtls-rprx-vision',
                        servername='sni.example', **{'reality-opts': {'public-key': 'synthetic-key', 'short-id': '1234'}})
        p = egern.proxy(raw)['vless']
        self.assertEqual(p['flow'], 'xtls-rprx-vision')
        self.assertEqual(p['transport']['tls']['reality'], {'public_key': 'synthetic-key', 'short_id': '1234'})
        self.assertEqual(p['transport']['tls']['sni'], 'sni.example')
        raw.pop('flow'); raw.pop('reality-opts'); raw['network'] = 'ws'
        raw['ws-opts'] = {'path': '/path', 'headers': {'Host': 'ws.example'}}
        self.assertEqual(egern.proxy(raw)['vless']['transport']['wss']['path'], '/path')
        raw['network'] = 'xhttp'
        with self.assertRaises(ValueError): egern.proxy(raw)

    def test_current_pool_protocols_and_explicit_rejection(self):
        cases = [self.node('ss', cipher='chacha20-ietf-poly1305', password='p'),
                 self.node('vmess', uuid='id', cipher='auto', alterId=0),
                 self.node('trojan', password='p', sni='sni.example'),
                 self.node('hysteria2', password='p', ports='443,8443', **{'hop-interval': 30}),
                 self.node('tuic', uuid='id', password='p', alpn=['h3'], **{'udp-relay-mode': 'native'}),
                 self.node('anytls', password='p')]
        converted = [egern.proxy(x) for x in cases]
        self.assertEqual(converted[0]['shadowsocks']['method'], 'chacha20-poly1305')
        self.assertEqual(converted[3]['hysteria2']['auth'], 'p')
        self.assertEqual(converted[3]['hysteria2']['port_hopping'], '443,8443')
        self.assertEqual(converted[4]['tuic']['uuid'], 'id')
        with self.assertRaises(ValueError): egern.proxy(self.node('mieru'))
        with self.assertRaises(ValueError): egern.proxy(self.node('ss', cipher='none', password='p', plugin='v2ray-plugin'))

    def test_ordered_rules_geo_conversion_and_unsupported_host_notice(self):
        rules, skipped = egern.rules(['GEOSITE,youtube,Video', 'GEOIP,telegram,Chat,no-resolve',
            'GEOIP,CN,DIRECT,no-resolve', 'PROCESS-NAME,test,DIRECT', 'DOMAIN-REGEX,^a{1,2}\\.com$,Video',
            'GEOIP,private,DIRECT,no-resolve', 'MATCH,Video'], 'https://sc.example')
        self.assertIn('/egern/rules?', rules[0]['rule_set']['match'])
        self.assertEqual(rules[2], {'geoip': {'match': 'CN', 'policy': 'DIRECT', 'no_resolve': True}})
        self.assertEqual(rules[3]['domain_regex']['match'], '^a{1,2}\\.com$')
        self.assertEqual(rules[-1], {'default': {'policy': 'Video'}})
        self.assertEqual(skipped, {'PROCESS-NAME': 1})
        out = egern.load(egern.ruleset(b'payload:\n  - DOMAIN-REGEX,^ads\\.\n  - DOMAIN-SUFFIX,example.com\n  - IP-CIDR,10.0.0.0/8,no-resolve\n  - IP-CIDR,fc00::/7\n'))
        self.assertEqual(out['domain_regex_set'], ['^ads\\.'])
        self.assertEqual(out['domain_suffix_set'], ['example.com'])
        self.assertTrue(out['no_resolve'])
        self.assertEqual(out['ip_cidr6_set'], ['fc00::/7'])
        import base64
        from urllib.parse import urlsplit, parse_qs
        encoded = parse_qs(urlsplit(rules[-2]['rule_set']['match']).query)['url'][0]
        self.assertTrue(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode().endswith('/geoip/classical/private.list'))
        with self.assertRaises(ValueError): egern.rules(['UNKNOWN,x,Video'], 'https://example.com')

    def test_smart_is_inside_pools_and_last_resort_order_survives(self):
        source = {'proxies': [self.node('trojan', password='p')], 'proxy-groups': [
            {'name': 'WM', 'type': 'load-balance', 'proxies': ['trojan']},
            {'name': 'AI', 'type': 'fallback', 'proxies': ['trojan']},
            {'name': 'Backup', 'type': 'fallback', 'proxies': ['REJECT']},
            {'name': 'Daily', 'type': 'fallback', 'proxies': ['WM', 'Backup']},
            {'name': 'Select', 'type': 'select', 'proxies': ['Daily']}], 'rules': ['MATCH,Select']}
        base = {'_wwmm': {'smart_groups': ['AI'], 'daily_smart': {'Daily': 'WM'}}, 'modules': []}
        result = egern.load(egern.render(egern.dump(source), 'https://sc.example', base, 'https://sc.example/my/sub?token=synthetic'))
        groups = {next(iter(x.values()))['name']: x for x in result['policy_groups']}
        self.assertIn('smart', groups['AI']); self.assertIn('load_balance', groups['WM'])
        self.assertEqual(groups['Daily']['fallback']['policies'], ['🧠 日常智能', 'Backup'])
        self.assertEqual(groups['Select']['select']['policies'], ['Daily', 'WM'])
        self.assertEqual(result['auto_update']['interval'], 86400)
        self.assertNotIn('_wwmm', result)
        source['proxy-groups'][0]['proxies'] = ['Select']
        with self.assertRaises(ValueError): egern.render(egern.dump(source), 'https://sc.example')


if __name__ == '__main__': unittest.main()
