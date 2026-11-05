"""Public conversion and fixed private presets; private converters have a separate network."""
import base64
from collections import defaultdict, deque
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import time
import tempfile
import egern
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
SETTINGS_FILE = Path(os.environ.get('SETTINGS_FILE', '/data/settings.json'))
EGERN_FILE = Path(os.environ.get('EGERN_FILE', '/egern/base.yaml'))
PRIVATE_TARGETS = ('loon', 'clash', 'egern')
ORIGIN = os.environ.get('PUBLIC_ORIGIN', 'https://sc.wwmm.date').rstrip('/')
PUBLIC_BACKEND = os.environ.get('PUBLIC_BACKEND', 'http://public-converter:25500')
PRIVATE_BACKEND = os.environ.get('PRIVATE_BACKEND', 'http://private-converter:25500')
PUBLIC_ARGS = {'target', 'url', 'config', 'include', 'exclude', 'emoji', 'add_emoji', 'remove_emoji',
               'udp', 'tfo', 'scv', 'sort', 'list', 'new_name', 'append_type', 'fdn', 'expand',
               'classic', 'ver', 'interval', 'append_info', 'filename'}
URI_SCHEMES = {'ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria2', 'hy2', 'tuic', 'anytls', 'socks5'}
# This public list contains only DOMAIN-SUFFIX rules, already understood by Loon.
# Redirect its 110k entries to the source instead of relaying megabytes through the VPS.
DIRECT_SURGE_RULES = {'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/cn.list'}
TARGETS = {'clash', 'clashr', 'loon', 'surge', 'surfboard', 'mellow', 'quan', 'quanx', 'ss',
           'ssr', 'vless', 'trojan', 'hysteria2', 'mixed', 'sssub', 'singbox', 'v2ray', 'ssd', 'auto', 'egern'}
LIMIT = threading.BoundedSemaphore(4)
AUTH_FAILURES = defaultdict(deque)
AUTH_LOCK = threading.Lock()


class BusyError(Exception):
    pass


def settings():
    data = json.loads(SETTINGS_FILE.read_text())
    if len(data.get('admin_key', '')) < 12 or any(len(data.get('tokens', {}).get(t, '')) < 32 for t in PRIVATE_TARGETS):
        raise ValueError('Private preset credentials are not configured')
    return data


def equal(left, right):
    return bool(left and right) and hmac.compare_digest(left.encode(), right.encode())


def validate_http(raw):
    url = urlsplit(raw)
    if url.scheme not in ('https', 'http') or not url.hostname or url.username or url.password:
        raise ValueError('请使用公开的 HTTP / HTTPS 地址')
    host = url.hostname.lower()
    if host in ('localhost', 'public-converter', 'private-converter', 'web') or host.endswith(('.localhost', '.local', '.internal')) or '.' not in host:
        raise ValueError('不允许本地或内部地址')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError('不允许本地或内部地址')


def public_query(values):
    if set(values) - PUBLIC_ARGS or values.get('target', 'auto') not in TARGETS:
        raise ValueError('不支持的转换参数')
    for raw in re.split(r'[|\r\n]+', values.get('url', '')):
        if not raw:
            continue
        if urlsplit(raw).scheme not in URI_SCHEMES:
            validate_http(raw)
    if not values.get('url'):
        raise ValueError('请填写订阅地址')
    if values.get('config'):
        validate_http(values['config'])
    if len(urlencode(values)) > 60000:
        raise ValueError('转换地址过长')
    return '/sub?' + urlencode(values)


def convert(path, private=False):
    endpoint = (PRIVATE_BACKEND if private else PUBLIC_BACKEND) + path
    request = Request(endpoint, headers={'User-Agent': 'Mozilla/5.0 (WWMM-Sub-Web/1.0)'})
    if not LIMIT.acquire(timeout=1): raise BusyError()
    try:
        with urlopen(request, timeout=180) as response:
            body = response.read(32 * 1024 * 1024 + 1)
            if len(body) > 32 * 1024 * 1024:
                raise ValueError('生成结果过大')
            headers = {name: response.headers[name] for name in ('Subscription-UserInfo', 'profile-update-interval') if name in response.headers}
            return body, headers
    finally:
        LIMIT.release()


def summarize(body, target):
    text = body.decode('utf-8-sig')
    if target == 'egern':
        return egern.summary(body)
    if target == 'loon':
        section = ''
        counts = {'nodes': 0, 'groups': 0}
        pool_counts = defaultdict(int)
        for line in text.splitlines():
            if re.fullmatch(r'\[.*\]', line.strip()):
                section = line.strip()
            elif '=' in line and not line.lstrip().startswith(('#', ';')):
                if section == '[Proxy]':
                    counts['nodes'] += 1
                    match = re.search(r'\[(WM|DAILY|AI|AI-BACKUP|BACKUP|CATHY)\]', line.split('=', 1)[0])
                    if match: pool_counts[match[1]] += 1
                if section == '[Proxy Group]': counts['groups'] += 1
        if re.search(r'^GEOSITE,', text, re.M):
            raise ValueError('Loon 配置仍包含不支持的 GEOSITE，请检查共用规则')
        counts['pool_counts'] = dict(pool_counts)
    else:
        section = False
        items = []
        for line in text.splitlines():
            if re.match(r'^proxies:\s*$', line): section = True; continue
            if section and re.match(r'^[A-Za-z][^:]*:', line): break
            if section and re.match(r'^\s*-\s+', line): items.append(len(line) - len(line.lstrip()))
        counts = {'nodes': sum(i == min(items) for i in items) if items else 0}
    if not counts['nodes']:
        raise ValueError('没有生成可用节点，请检查 Sub-Store 输出')
    return counts


def compatible_rules(body):
    # The legacy exporter matches type prefixes, which also admits DOMAIN-REGEX.
    allowed = {b'DOMAIN', b'DOMAIN-SUFFIX', b'DOMAIN-KEYWORD', b'IP-CIDR', b'IP-CIDR6',
               b'SRC-IP-CIDR', b'GEOIP', b'IP-ASN', b'USER-AGENT', b'URL-REGEX',
               b'AND', b'OR', b'NOT', b'PROCESS-NAME', b'IN-PORT', b'DEST-PORT', b'SRC-IP'}
    return b'\n'.join(line for line in body.splitlines() if line.strip().split(b',', 1)[0] in allowed) + b'\n'


def adapt_loon(body):
    remote = False
    lines = []
    for line in body.decode('utf-8-sig').splitlines():
        stripped = line.strip()
        if re.fullmatch(r'\[.*\]', stripped): remote = stripped.lower() == '[remote rule]'
        if remote and stripped.startswith(('https://', 'http://')):
            url, separator, policy = stripped.partition(',')
            if separator and not url.startswith(ORIGIN + '/getruleset?'):
                validate_http(url)
                encoded = base64.urlsafe_b64encode(('surge:' + url).encode()).decode().rstrip('=')
                line = ORIGIN + '/getruleset?' + urlencode({'type': '1', 'url': encoded}) + ',' + policy
        lines.append(line)
    return ('\n'.join(lines) + '\n').encode()


def egern_base(private=False):
    path = EGERN_FILE if private else ROOT/'egern-base.yaml'
    return egern.validate_base(path.read_bytes())


def adapt_egern(body, private=False, update_url=None, nodes_only=False):
    return egern.render(body, ORIGIN, egern_base(private), update_url, nodes_only)


def save_egern_base(raw):
    egern.validate_base(raw)
    # Dedicated writable Egern volume; the existing Loon certificates remain read-only.
    with tempfile.NamedTemporaryFile(mode='w', dir=EGERN_FILE.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(raw); file.flush(); os.fsync(file.fileno())
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    try: os.replace(temporary, EGERN_FILE)
    finally: temporary.unlink(missing_ok=True)


class Handler(BaseHTTPRequestHandler):
    server_version = 'WWMM-Sub'

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, fmt, *args):
        # URLs can contain subscription/download credentials. Never log query strings.
        pass

    def send(self, code, body, kind='application/json; charset=utf-8', extra=None):
        if not isinstance(body, bytes): body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        for name, value in {'Content-Type': kind, 'Content-Length': str(len(body)),
                            'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                            'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
                            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", **(extra or {})}.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(body)

    def authenticated(self, expected, supplied):
        if equal(supplied, expected): return True
        address = self.headers.get('X-Forwarded-For', self.client_address[0]).split(',')[0].strip()[:80]
        now = time.monotonic()
        with AUTH_LOCK:
            for key in list(AUTH_FAILURES):
                while AUTH_FAILURES[key] and AUTH_FAILURES[key][0] < now - 60: AUTH_FAILURES[key].popleft()
                if not AUTH_FAILURES[key]: del AUTH_FAILURES[key]
            if len(AUTH_FAILURES) > 4096: AUTH_FAILURES.clear()
            failures = AUTH_FAILURES[address]
            failures.append(now)
            limited = len(failures) > 20
        self.send(429 if limited else 401, {'error': '请求过于频繁' if limited else '密钥无效或缺失'})
        return False

    def private_profile(self, target, data):
        return '/getprofile?' + urlencode({'name': 'private/' + ('clash' if target == 'egern' else target) + '.ini', 'token': data.get('backend_token', data['tokens'][target])})

    def preset_info(self, data):
        return {'pools': data.get('pools', []), 'downloads': {
            t: ORIGIN + '/my/sub?' + urlencode({'target': t, 'token': data['tokens'][t]}) for t in PRIVATE_TARGETS}}

    def private_output(self, target, data):
        body, headers = convert(self.private_profile(target, data), True)
        if target == 'loon': body = adapt_loon(body)
        if target == 'egern': body = adapt_egern(body, True, self.preset_info(data)['downloads'][target])
        return body, headers

    def do_GET(self): self.dispatch()
    def do_HEAD(self): self.dispatch()
    def do_POST(self): self.dispatch()

    def dispatch(self):
        try:
            if len(self.path) > 65536: raise ValueError('请求过长')
            parsed = urlsplit(self.path)
            pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=40)
            values = dict(pairs)
            if len(values) != len(pairs): raise ValueError('不允许重复参数')
            path = parsed.path
            if self.command in ('GET', 'HEAD') and path in ('/', '/app.js', '/style.css'):
                name = 'index.html' if path == '/' else path[1:]
                kind = {'index.html': 'text/html; charset=utf-8', 'app.js': 'text/javascript; charset=utf-8', 'style.css': 'text/css; charset=utf-8'}[name]
                return self.send(200, (ROOT/'web'/name).read_bytes(), kind)
            if path == '/healthz' and self.command in ('GET', 'HEAD'):
                return self.send(200, {'status': 'ok', 'version': 'wwmm-20261105'})
            if path == '/sub' and self.command in ('GET', 'HEAD'):
                query = public_query(values)
                if values.get('target') == 'egern':
                    query = public_query({**values, 'target': 'clash', 'new_name': 'true', 'expand': 'true'})
                body, headers = convert(query)
                if values.get('target') == 'loon': body = adapt_loon(body)
                if values.get('target') == 'egern':
                    body = adapt_egern(body, nodes_only=values.get('list') == 'true')
                return self.send(200, body, 'text/plain; charset=utf-8', headers)
            if path == '/egern/rules' and self.command in ('GET', 'HEAD'):
                if set(values) != {'url'}: raise ValueError('Invalid rule request')
                encoded = values['url']
                decoded = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode()
                source = decoded
                for prefix in ('clash-classic:', 'clash-domain:', 'clash-ipcidr:', 'surge:', 'quanx:'):
                    if source.startswith(prefix): source = source[len(prefix):]; break
                validate_http(source)
                raw, _ = convert('/getruleset?' + urlencode({'type': '6', 'url': encoded}))
                return self.send(200, egern.ruleset(raw), 'application/yaml; charset=utf-8')
            if path == '/getruleset' and self.command in ('GET', 'HEAD'):
                if set(values) - {'type', 'url', 'group'} or values.get('type') not in ('1', '2', '3', '4', '5', '6'):
                    raise ValueError('规则参数无效')
                raw = values.get('url', '')
                decoded = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode()
                for prefix in ('clash-classic:', 'clash-domain:', 'clash-ipcidr:', 'surge:', 'quanx:'):
                    if decoded.startswith(prefix): decoded = decoded[len(prefix):]; break
                validate_http(decoded)
                if values['type'] == '1' and decoded in DIRECT_SURGE_RULES:
                    return self.send(302, b'', 'text/plain; charset=utf-8', {'Location': decoded})
                body, _ = convert('/getruleset?' + urlencode(values))
                if values['type'] == '1': body = compatible_rules(body)
                return self.send(200, body, 'text/plain; charset=utf-8')
            if path == '/my/sub' and self.command in ('GET', 'HEAD'):
                if set(values) - {'target', 'token'} or values.get('target') not in PRIVATE_TARGETS:
                    raise ValueError('私有配置只接受客户端类型和下载密钥')
                data, target = settings(), values['target']
                if not self.authenticated(data['tokens'][target], values.get('token', '')): return
                body, headers = self.private_output(target, data)
                summarize(body, target)
                headers['Content-Disposition'] = 'attachment; filename="wwmm-' + target + ('.conf"' if target == 'loon' else '.yaml"')
                return self.send(200, body, 'text/plain; charset=utf-8', headers)
            if path in ('/api/presets', '/api/generate', '/api/egern-settings'):
                if values: raise ValueError('管理密钥必须通过请求头传递')
                data = settings()
                key = self.headers.get('Authorization', '').removeprefix('Bearer ')
                if not self.authenticated(data['admin_key'], key): return
                if path == '/api/egern-settings':
                    if self.command == 'GET':
                        return self.send(200, {'yaml': EGERN_FILE.read_text()})
                    if self.command == 'POST':
                        length = int(self.headers.get('Content-Length', '0'))
                        if not 0 < length <= 131072: raise ValueError('Invalid settings size')
                        payload = json.loads(self.rfile.read(length))
                        if not isinstance(payload, dict) or set(payload) != {'yaml'} or not isinstance(payload['yaml'], str):
                            raise ValueError('Invalid settings body')
                        save_egern_base(payload['yaml'])
                        return self.send(200, {'saved': True})
                if path == '/api/presets' and self.command == 'GET':
                    return self.send(200, self.preset_info(data))
                if path == '/api/generate' and self.command == 'POST':
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 1024: raise ValueError('请求内容无效')
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict) or set(body) != {'target'} or body['target'] not in PRIVATE_TARGETS:
                        raise ValueError('请选择 Loon、Clash 或 Egern')
                    target = body['target']
                    result, _ = self.private_output(target, data)
                    return self.send(200, {**summarize(result, target), 'download': self.preset_info(data)['downloads'][target]})
            return self.send(404, {'error': 'Not found'})
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, egern.yaml.YAMLError, json.JSONDecodeError):
            self.send(400, {'error': '请求或生成结果无效，请检查订阅、参数和规则'})
        except (HTTPError, URLError, TimeoutError, OSError):
            self.send(502, {'error': '转换失败，请检查订阅是否可用后重试'})
        except BusyError:
            self.send(503, {'error': '转换服务繁忙，请稍后重试'}, extra={'Retry-After': '5'})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        self.workers = threading.BoundedSemaphore(12)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try: super().process_request_thread(request, client_address)
        finally: self.workers.release()


if __name__ == '__main__':
    settings()  # Fail closed when private credentials are missing.
    Server(('0.0.0.0', int(os.environ.get('PORT', '8080'))), Handler).serve_forever()
