const $ = (id) => document.getElementById(id);
let privateKey = '';
let mode = 'public';
let lastPrivateResult = false;
let savedEgernSettings = '';
const clientNames = { loon: 'Loon', clash: 'Clash / OpenClash', egern: 'Egern' };

function message(text, error = false) {
  $('status').textContent = text;
  $('status').classList.toggle('error', error);
}
function showMode(next) {
  mode = next;
  $('public-panel').hidden = mode !== 'public';
  $('private-panel').hidden = mode !== 'private';
  $('public-tab').setAttribute('aria-pressed', String(mode === 'public'));
  $('private-tab').setAttribute('aria-pressed', String(mode === 'private'));
  $('result').hidden = true;
  message('');
}
$('public-tab').addEventListener('click', () => showMode('public'));
$('private-tab').addEventListener('click', () => showMode('private'));
$('rule').addEventListener('change', () => {
  $('custom-rule-label').hidden = $('rule').value !== 'custom';
  $('custom-rule').required = $('rule').value === 'custom';
});
$('private-target').addEventListener('change', () => {
  const target = $('private-target').value;
  $('private-settings-title').textContent = {loon: 'Loon 私有设置', clash: 'Clash 基础设置', egern: 'Egern · Smart 设置'}[target];
  $('private-note').textContent = {loon: '沿用服务器保存的个人证书、插件、Script 和 DNS。', clash: '使用相同的六个用途池和共用规则，加入 Clash 基础设置。', egern: '共用节点池与分流规则，日常和 AI 使用 Smart，外层保留故转与最后备用。'}[target];
  $('egern-editor').hidden = target !== 'egern';
  if (target === 'egern' && privateKey && !savedEgernSettings) loadEgernSettings().catch((error) => message(error.message, true));
  $('result').hidden = true;
});
document.querySelectorAll('[data-private-target]').forEach((button) => {
  button.addEventListener('click', () => {
    $('private-target').value = button.dataset.privateTarget;
    document.querySelectorAll('[data-private-target]').forEach((target) => {
      target.setAttribute('aria-pressed', String(target === button));
    });
    $('private-target').dispatchEvent(new Event('change'));
  });
});
async function api(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', ...options });
  if (!response.ok) {
    let info;
    try { info = await response.json(); } catch (_) { info = {}; }
    throw new Error(info.error || '请求失败，请稍后重试');
  }
  return response;
}
async function busy(form, action) {
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  form.setAttribute('aria-busy', 'true');
  $('result').hidden = true;
  try { await action(); } catch (error) { message(error.message, true); }
  finally { button.disabled = false; form.removeAttribute('aria-busy'); }
}
function result(url, target, info, personal) {
  lastPrivateResult = personal;
  $('output').value = url;
  $('download').href = url;
  $('result-title').textContent = clientNames[target] + ' 配置已生成';
  $('counts').textContent = info && info.nodes ? `${info.nodes} 个节点${info.groups ? ` · ${info.groups} 个策略组` : ''}` : '';
  $('result-note').textContent = personal ? '固定私有链接；请勿公开分享' : '使用你填写的订阅和规则';
  $('result').hidden = false;
}
$('public-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    const values = new URLSearchParams({
      target: $('public-target').value,
      url: $('subscriptions').value.trim().split(/[\r\n]+/).map((line) => line.trim()).filter(Boolean).join('|'),
      config: $('rule').value === 'custom' ? $('custom-rule').value.trim() : $('rule').value,
      new_name: 'true', emoji: String($('emoji').checked), udp: String($('udp').checked),
      scv: String($('scv').checked), list: 'false', sort: 'false',
    });
    for (const name of ['include', 'exclude']) if ($(name).value.trim()) values.set(name, $(name).value.trim());
    const url = location.origin + '/sub?' + values;
    message('正在转换并验证，请稍候…');
    const response = await api('/sub?' + values);
    const text = await response.text();
    if (!text.includes('[Proxy]') && !text.includes('proxies:')) throw new Error('未生成有效配置，请检查订阅格式与规则');
    result(url, values.get('target'), null, false);
    message('生成成功。复制链接到客户端，或下载配置。');
  });
});
$('unlock-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    const key = $('key').value.trim();
    message('正在读取你的预设…');
    const response = await api('/api/presets', { headers: { Authorization: 'Bearer ' + key } });
    const data = await response.json();
    privateKey = key;
    $('key').value = '';
    const descriptions = {
      'WM 均衡': '日常负载均衡', '日常主用': '网页 / YouTube / Telegram',
      'AI 优先': 'AI 优先使用的节点', 'AI 后备': 'AI 优先池不可用时接替',
      '最后备用': '其他池不可用时兜底', 'Cathy 专用': '仅用于 Cathy 专用分组',
    };
    $('pools').replaceChildren(...data.pools.map((name) => {
      const element = document.createElement('div'); element.className = 'pool';
      const check = document.createElement('span'); check.className = 'pool-check'; check.textContent = '✓'; check.setAttribute('aria-hidden', 'true');
      const content = document.createElement('span');
      const title = document.createElement('strong'); title.textContent = name;
      const detail = document.createElement('small'); detail.textContent = descriptions[name] || '引用 Sub-Store 组合的最新输出';
      content.append(title, detail); element.append(check, content); return element;
    }));
    $('auth-state').textContent = '已解锁';
    $('auth-state').classList.add('unlocked');
    $('unlock-form').hidden = true;
    $('unlocked').hidden = false;
    $('private-target').dispatchEvent(new Event('change'));
    message('预设已解锁，选择客户端后即可重新生成。');
  });
});
$('private-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    message('正在读取六个用途池并生成配置，请稍候…');
    const target = $('private-target').value;
    if (target === 'egern' && $('egern-settings').value !== savedEgernSettings) throw new Error('请先保存 Egern 设置，或重新加载已保存的内容。');
    const response = await api('/api/generate', {
      method: 'POST', headers: { Authorization: 'Bearer ' + privateKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    const data = await response.json();
    result(data.download, target, data, true);
    const missing = data.pool_counts && !data.pool_counts['AI-BACKUP'];
    const warnings = data.warnings && data.warnings.length ? ' Egern 已略过进程名等不支持的规则，详情见下载文件顶部注释。' : '';
    message((missing ? '已生成。AI 后备池当前没有可用节点，请在 Sub-Store 检查 MESL 订阅；其他池继续按故转顺序使用。' : '已生成并验证。客户端继续使用这条固定链接获取最新配置。') + warnings);
  });
});
$('lock').addEventListener('click', () => {
  privateKey = '';
  savedEgernSettings = '';
  $('egern-settings').value = '';
  $('unlock-form').hidden = false;
  $('unlocked').hidden = true;
  $('pools').replaceChildren();
  $('auth-state').textContent = '需要密钥';
  $('auth-state').classList.remove('unlocked');
  if (lastPrivateResult) { $('result').hidden = true; $('output').value = ''; $('download').removeAttribute('href'); }
  message('私有预设已锁定。');
});
$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('output').value); message('链接已复制。'); }
  catch (_) { $('output').focus(); $('output').select(); message('请长按复制，或按 ⌘C / Ctrl+C。'); }
});
if (location.hash === '#my') showMode('private');

async function loadEgernSettings() {
  const key = privateKey;
  const response = await api('/api/egern-settings', {headers: {Authorization: 'Bearer ' + key}});
  const data = await response.json();
  if (key !== privateKey) return;
  savedEgernSettings = data.yaml;
  $('egern-settings').value = data.yaml;
  $('egern-settings-state').textContent = '已读取服务器设置';
}
$('egern-settings').addEventListener('input', () => {
  $('egern-settings-state').textContent = $('egern-settings').value === savedEgernSettings ? '已保存' : '有未保存的修改';
});
$('reload-egern-settings').addEventListener('click', () => loadEgernSettings().catch((error) => message(error.message, true)));
$('save-egern-settings').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  const yaml = $('egern-settings').value;
  const key = privateKey;
  try {
    await api('/api/egern-settings', {method: 'POST', headers: {Authorization: 'Bearer ' + key, 'Content-Type': 'application/json'}, body: JSON.stringify({yaml})});
    if (key !== privateKey) return;
    savedEgernSettings = yaml;
    $('egern-settings-state').textContent = $('egern-settings').value === yaml ? '已保存' : '有未保存的修改';
    message('Egern 设置已保存；重新生成或客户端更新配置时生效。');
  } catch (error) { message(error.message, true); }
  finally { button.disabled = false; }
});
