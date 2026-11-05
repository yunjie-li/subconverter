"""Egern renderer for the shared INI's Clash intermediate representation.

Schema: https://egernapp.com/docs/configuration/{proxies,policy_groups,rules}/
Unknown node/transport/rule types fail closed instead of silently losing traffic.
"""
from collections import Counter
from copy import deepcopy
import base64
import re
from urllib.parse import urlencode
import yaml

Loader = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)
Dumper = getattr(yaml, 'CSafeDumper', yaml.SafeDumper)
COUNTRIES = re.compile(r'^[A-Z]{2}$')
TYPES = {'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword',
         'DOMAIN-REGEX': 'domain_regex', 'DOMAIN-WILDCARD': 'domain_wildcard', 'IP-CIDR': 'ip_cidr',
         'IP-CIDR6': 'ip_cidr6', 'IP-ASN': 'asn', 'DST-PORT': 'dest_port', 'DEST-PORT': 'dest_port',
         'NETWORK': 'protocol', 'URL-REGEX': 'url_regex', 'USER-AGENT': 'user_agent'}
# These Clash host-process rules have no equivalent in Egern's documented rule schema.
HOST_ONLY = {'PROCESS-NAME', 'PROCESS-PATH', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX', 'SRC-PORT', 'IN-PORT'}



def load(raw):
    value = yaml.load(raw, Loader=Loader)
    if not isinstance(value, dict): raise ValueError('Expected YAML mapping')
    return value


def dump(value):
    return yaml.dump(value, Dumper=Dumper, allow_unicode=True, sort_keys=False).encode()


def picked(source, mapping):
    return {dest: source[src] for src, dest in mapping.items() if source.get(src) is not None}


def tls_options(p):
    result = picked(p, {'skip-cert-verify': 'skip_tls_verify', 'fingerprint': 'fingerprint_sha256'})
    result['sni'] = p.get('servername') or p.get('sni') or p['server']
    if p.get('reality-opts'):
        result['reality'] = picked(p['reality-opts'], {'public-key': 'public_key', 'short-id': 'short_id'})
        if not result['reality'].get('public_key'): raise ValueError('Missing Reality key')
    return result


def transport(p):
    network = p.get('network') or 'tcp'
    tls = tls_options(p) if p.get('tls') else {}
    if network == 'tcp': return {'tls': tls} if tls else None
    if network == 'ws':
        opts = p.get('ws-opts', {})
        if opts.get('v2ray-http-upgrade') or opts.get('max-early-data'):
            raise ValueError('Unsupported Egern WebSocket upgrade/early data')
        return {'wss' if tls else 'ws': {**picked(opts, {'path': 'path', 'headers': 'headers'}), **tls}}
    if network == 'grpc':
        if not tls or p.get('grpc-opts', {}).get('grpc-mode', 'gun') != 'gun':
            raise ValueError('Egern gRPC requires TLS and gun mode')
        return {'grpc': {**picked(p.get('grpc-opts', {}), {'grpc-service-name': 'service_name'}), **tls}}
    if network == 'h2':
        opts = p.get('h2-opts', {})
        return {'http2': {**picked(opts, {'path': 'path'}), 'headers': {'Host': (opts.get('host') or [p['server']])[0]}, **tls}}
    raise ValueError('Unsupported Egern transport')


def proxy(p):
    kind = p['type']
    names = {'ss': 'shadowsocks', 'ssr': 'shadowsocksr', 'vmess': 'vmess', 'vless': 'vless',
             'trojan': 'trojan', 'hysteria2': 'hysteria2', 'tuic': 'tuic', 'anytls': 'anytls',
             'http': 'https' if p.get('tls') else 'http', 'socks5': 'socks5_tls' if p.get('tls') else 'socks5',
             'snell': 'snell', 'wireguard': 'wireguard'}
    if kind not in names: raise ValueError('Unsupported Egern node protocol: ' + kind)
    out = picked(p, {'name': 'name', 'server': 'server', 'port': 'port', 'tfo': 'tfo', 'udp': 'udp_relay',
                     'dialer-proxy': 'prev_hop', 'ip-version': 'ip_version'})
    if 'ip_version' in out:
        out['ip_version'] = {'dual': 'dual_stack', 'ipv4': 'v4_only', 'ipv6': 'v6_only',
                             'ipv4-prefer': 'v4_prefer', 'ipv6-prefer': 'v6_prefer'}[out['ip_version']]
    if kind in {'vmess', 'vless'}:
        out['user_id'] = p['uuid']
        tr = transport(p)
        if tr: out['transport'] = tr
        if kind == 'vmess':
            out['security'] = {'chacha20-ietf-poly1305': 'chacha20-poly1305'}.get(p.get('cipher'), p.get('cipher', 'auto'))
            out['legacy'] = bool(p.get('alterId', 0))
        elif p.get('flow'):
            if p['flow'] != 'xtls-rprx-vision' or not p.get('tls') or (p.get('network') or 'tcp') != 'tcp':
                raise ValueError('Unsupported Egern VLESS flow')
            out['flow'] = p['flow']
        if kind == 'vless' and p.get('encryption', 'none') != 'none': raise ValueError('Unsupported VLESS encryption')
    elif kind in {'ss', 'ssr'}:
        out.update(picked(p, {'password': 'password', 'cipher': 'method'}))
        if out['method'] == 'chacha20-ietf-poly1305': out['method'] = 'chacha20-poly1305'
        if kind == 'ssr': out.update(picked(p, {'protocol': 'protocol', 'protocol-param': 'protocol_param', 'obfs': 'obfs', 'obfs-param': 'obfs_param'}))
        plugin = p.get('plugin')
        if plugin:
            opts = p.get('plugin-opts', {})
            if plugin == 'obfs': out.update(picked(opts, {'mode': 'obfs', 'host': 'obfs_host', 'path': 'obfs_uri'}))
            elif plugin == 'shadow-tls' and opts.get('version') == 3:
                out['shadow_tls'] = picked(opts, {'password': 'password', 'host': 'sni'})
            else: raise ValueError('Unsupported Egern Shadowsocks plugin')
    elif kind == 'wireguard':
        if p.get('peers'): raise ValueError('Multi-peer WireGuard needs explicit Egern mapping')
        out.update(picked(p, {'private-key': 'private_key', 'public-key': 'peer_public_key',
                              'preshared-key': 'preshared_key', 'reserved': 'reserved', 'dns': 'dns_servers', 'mtu': 'mtu'}))
        for src, dest, mask in [('ip', 'local_ipv4', '32'), ('ipv6', 'local_ipv6', '128')]:
            if p.get(src): out[dest] = p[src] if '/' in p[src] else p[src] + '/' + mask
    elif kind == 'snell':
        out.update(picked(p, {'psk': 'psk', 'version': 'version'}))
        out.update(picked(p.get('obfs-opts', {}), {'mode': 'obfs', 'host': 'obfs_host'}))
    else:
        out.update(picked(p, {'password': 'password', 'username': 'username'}))
        if kind in {'trojan', 'anytls', 'hysteria2', 'tuic'} or p.get('tls'): out.update(tls_options(p))
        if kind == 'trojan':
            network = p.get('network') or 'tcp'
            if network == 'ws':
                opts = p.get('ws-opts', {})
                out['websocket'] = {**picked(opts, {'path': 'path'}), **picked(opts.get('headers', {}), {'Host': 'host'})}
            elif network != 'tcp': raise ValueError('Unsupported Trojan transport')
        if kind == 'anytls' and p.get('network', 'tcp') != 'tcp': raise ValueError('Unsupported AnyTLS transport')
        if kind == 'hysteria2':
            out.pop('password', None)
            out['auth'] = p.get('password') or p.get('auth')
            out.update(picked(p, {'ports': 'port_hopping', 'hop-interval': 'port_hopping_interval',
                                  'obfs': 'obfs', 'obfs-password': 'obfs_password'}))
        if kind == 'tuic':
            if p.get('token') or p.get('disable-sni'): raise ValueError('Unsupported TUIC v4 or disabled SNI')
            out.update(picked(p, {'uuid': 'uuid', 'alpn': 'alpn', 'udp-relay-mode': 'udp_relay_mode',
                                  'ports': 'port_hopping', 'hop-interval': 'port_hopping_interval'}))
    return {names[kind]: out}


def rule_url(source, origin):
    return origin + '/egern/rules?' + urlencode({'url': base64.urlsafe_b64encode(source.encode()).decode().rstrip('=')})


def rules(lines, origin, providers=None):
    result, skipped = [], Counter()
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('#', '//')): continue
        no_resolve = line.endswith(',no-resolve')
        if no_resolve: line = line[:-11]
        kind, rest = line.split(',', 1)
        if kind in HOST_ONLY: skipped[kind] += 1; continue
        if kind in {'MATCH', 'FINAL'}:
            result.append({'default': {'policy': rest}}); continue
        value, policy = rest.rsplit(',', 1)
        item = {'match': value, 'policy': policy}
        if kind in TYPES:
            target = 'ip_cidr6' if kind == 'IP-CIDR' and ':' in value else TYPES[kind]
            if no_resolve and target in {'ip_cidr', 'ip_cidr6', 'asn'}: item['no_resolve'] = True
            if target == 'protocol': item['match'] = value.lower()
            result.append({target: item})
        elif kind in {'GEOSITE', 'GEOIP', 'RULE-SET'}:
            if kind == 'GEOIP' and COUNTRIES.fullmatch(value):
                if no_resolve: item['no_resolve'] = True
                result.append({'geoip': item}); continue
            if kind == 'RULE-SET':
                source = (providers or {}).get(value, {}).get('url')
                if not source: raise ValueError('Missing remote rule provider')
                behavior = (providers or {})[value].get('behavior', 'classical')
                prefix = {'classical': 'clash-classic:', 'domain': 'clash-domain:', 'ipcidr': 'clash-ipcidr:'}[behavior]
                source = prefix + source
            else:
                if not re.fullmatch(r'[A-Za-z0-9_@.!-]+', value): raise ValueError('Invalid geo category')
                category = 'geosite' if kind == 'GEOSITE' else 'geoip'
                source = 'surge:https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/' + category + '/classical/' + value.lower() + '.list'
            item['match'] = rule_url(source, origin)
            result.append({'rule_set': item})
        else: raise ValueError('Unsupported Egern rule type: ' + kind)
    return result, dict(skipped)


def ruleset(raw):
    """Convert a normalized Clash classical rule-provider to Egern set YAML."""
    payload = load(raw).get('payload')
    if not isinstance(payload, list): raise ValueError('Missing rule payload')
    out = {}
    for line in payload:
        if not isinstance(line, str): raise ValueError('Invalid rule entry')
        line = line.removesuffix(',no-resolve')
        if ',' not in line: continue
        kind, value = line.split(',', 1)
        if kind in HOST_ONLY: continue
        if kind not in TYPES: raise ValueError('Unsupported rule-set entry: ' + kind)
        target = ('ip_cidr6' if kind == 'IP-CIDR' and ':' in value else TYPES[kind]) + '_set'
        out.setdefault(target, []).append(value)
    # IP rule providers used by the shared INI must not trigger DNS lookups.
    if any(x in out for x in ['ip_cidr_set', 'ip_cidr6_set', 'asn_set']): out['no_resolve'] = True
    return dump(out)


def validate(profile):
    proxies = [next(iter(x.values()))['name'] for x in profile.get('proxies', [])]
    groups = {next(iter(x.values()))['name']: next(iter(x.values())) for x in profile.get('policy_groups', [])}
    names = set(proxies) | set(groups) | {'DIRECT', 'REJECT'}
    if len(proxies) != len(set(proxies)) or len(proxies) + len(groups) != len(profile.get('proxies', [])) + len(profile.get('policy_groups', [])):
        raise ValueError('Duplicate Egern names')
    if set(proxies) & set(groups): raise ValueError('Node/group name collision')
    visited, visiting = set(), set()
    def visit(name):
        if name in visiting: raise ValueError('Policy group cycle')
        if name in visited: return
        visiting.add(name)
        for child in groups[name].get('policies', []):
            if child not in names: raise ValueError('Unknown Egern policy')
            if child in groups: visit(child)
        visiting.remove(name); visited.add(name)
    for name in groups: visit(name)
    for rule in profile.get('rules', []):
        if next(iter(rule.values()))['policy'] not in names: raise ValueError('Unknown Egern rule policy')
    return profile


def render(raw, origin, base=None, update_url=None, nodes_only=False):
    source = load(raw)
    proxies = [proxy(p) for p in source.get('proxies', [])]
    if not proxies: raise ValueError('No Egern nodes')
    if nodes_only: return dump({'proxies': proxies})
    profile = deepcopy(base or {})
    options = profile.pop('_wwmm', {})
    profile['proxies'] = proxies
    groups = []
    types = {'select': 'select', 'url-test': 'auto_test', 'fallback': 'fallback', 'load-balance': 'load_balance'}
    for g in source.get('proxy-groups', []):
        if g['type'] not in types: raise ValueError('Unsupported Egern policy group')
        kind = 'smart' if g['name'] in options.get('smart_groups', []) or (g['type'] == 'url-test' and options.get('smart_auto_test', True)) else types[g['type']]
        value = {'name': g['name'], 'policies': g.get('proxies') or ['REJECT']}
        if g.get('icon'): value['icon'] = g['icon']
        if kind in {'auto_test', 'fallback', 'load_balance'}:
            value.update(picked(g, {'interval': 'interval', 'tolerance': 'tolerance'}))
            if g.get('url'): value['latency_test_url'] = g['url']
        if kind == 'load_balance': value['algorithm'] = 'round_robin' if g.get('strategy') == 'round-robin' else 'hash'
        if kind == 'smart' and options.get('priorities'): value['priorities'] = options['priorities']
        groups.append({kind: value})
    by_name = {next(iter(g.values()))['name']: next(iter(g.values())) for g in groups}
    for outer, pool in options.get('daily_smart', {}).items():
        if outer not in by_name and pool not in by_name: continue
        if outer not in by_name or pool not in by_name: raise ValueError('Missing daily Smart pool')
        smart_name = '🧠 日常智能'
        groups.append({'smart': {'name': smart_name, 'policies': deepcopy(by_name[pool]['policies'])}})
        by_name[outer]['policies'] = [smart_name if n == pool else n for n in by_name[outer]['policies']]
        # Keep the original load-balance group reachable as a manual alternative.
        for group in groups:
            if 'select' in group and outer in group['select']['policies'] and pool not in group['select']['policies']:
                group['select']['policies'].append(pool)
    profile['policy_groups'] = groups
    profile['rules'], skipped = rules(source.get('rules', []), origin, source.get('rule-providers'))
    if update_url: profile['auto_update'] = {'url': update_url, 'interval': 86400}
    validate(profile)
    note = '# Generated from the shared INI for Egern.\n'
    if skipped: note += '# Egern has no equivalent for host-only rules: ' + ', '.join(f'{k}={v}' for k, v in skipped.items()) + '\n'
    return note.encode() + dump(profile)


def validate_base(raw):
    base = load(raw)
    if any(k in base for k in ('proxies', 'policy_groups', 'rules', 'auto_update')):
        raise ValueError('Nodes, groups, rules and updates are generated from the shared INI')
    opts = base.get('_wwmm', {})
    if not isinstance(opts, dict) or set(opts) - {'smart_groups', 'daily_smart', 'priorities', 'smart_auto_test'}:
        raise ValueError('Invalid Smart settings')
    if not isinstance(opts.get('smart_groups', []), list) or any(not isinstance(x, str) for x in opts.get('smart_groups', [])):
        raise ValueError('Invalid Smart groups')
    daily = opts.get('daily_smart', {})
    if not isinstance(daily, dict) or len(daily) > 1 or any(not isinstance(k, str) or not isinstance(v, str) for k, v in daily.items()):
        raise ValueError('Invalid daily Smart mapping')
    priorities = opts.get('priorities', {})
    if not isinstance(priorities, dict): raise ValueError('Invalid Smart priorities')
    for key, value in priorities.items():
        if not isinstance(key, str) or not isinstance(value, (float, int)) or isinstance(value, bool) or not 0 <= value <= 1000:
            raise ValueError('Invalid Smart priority coefficient')
    if 'smart_auto_test' in opts and not isinstance(opts['smart_auto_test'], bool): raise ValueError('Invalid Smart flag')
    for key in ('modules', 'scriptings'):
        if key in base and not isinstance(base[key], list): raise ValueError('Invalid Egern resource list')
    return base


def summary(raw):
    profile = validate(load(raw))
    counts = Counter()
    for item in profile.get('proxies', []):
        name = next(iter(item.values()))['name']
        match = re.search(r'\[(WM|DAILY|AI|AI-BACKUP|BACKUP|CATHY)\]', name)
        if match: counts[match[1]] += 1
    warnings = [line[2:] for line in raw.decode().splitlines()[:3] if line.startswith('# Egern has no equivalent')]
    return {'nodes': len(profile.get('proxies', [])), 'groups': len(profile.get('policy_groups', [])),
            'pool_counts': dict(counts), 'warnings': warnings}
