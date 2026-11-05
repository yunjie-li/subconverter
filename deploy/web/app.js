const $ = (id) => document.getElementById(id);
let privateKey = '';
let mode = 'public';
let lastPrivateResult = false;

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
  $('private-note').textContent = $('private-target').value === 'loon'
    ? '自动加入服务器上维护的个人证书、插件、Script 和 DNS。'
    : '使用相同的六个用途池和共用规则，加入 Clash 基础设置。';
  $('result').hidden = true;
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
  $('result').hidden = true;
  try { await action(); } catch (error) { message(error.message, true); }
  finally { button.disabled = false; }
}
function result(url, target, info, personal) {
  lastPrivateResult = personal;
  $('output').value = url;
  $('download').href = url;
  $('result-title').textContent = (target === 'loon' ? 'Loon' : 'Clash / OpenClash') + ' 配置已生成';
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
    $('pools').replaceChildren(...data.pools.map((name) => {
      const element = document.createElement('div'); element.className = 'pool'; element.textContent = name; return element;
    }));
    $('unlock-form').hidden = true;
    $('unlocked').hidden = false;
    message('预设已读取。选择客户端后点击“重新生成并验证”。');
  });
});
$('private-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    message('正在读取六个用途池并生成配置，请稍候…');
    const target = $('private-target').value;
    const response = await api('/api/generate', {
      method: 'POST', headers: { Authorization: 'Bearer ' + privateKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    const data = await response.json();
    result(data.download, target, data, true);
    const missing = data.pool_counts && !data.pool_counts['AI-BACKUP'];
    message(missing ? '已生成。AI 后备池当前没有可用节点，请在 Sub-Store 检查 MESL 订阅；其他池继续按故转顺序使用。' : '已生成并验证。客户端继续使用这条固定链接获取最新配置。');
  });
});
$('lock').addEventListener('click', () => {
  privateKey = '';
  $('unlock-form').hidden = false;
  $('unlocked').hidden = true;
  $('pools').replaceChildren();
  if (lastPrivateResult) { $('result').hidden = true; $('output').value = ''; $('download').removeAttribute('href'); }
  message('私有预设已锁定。');
});
$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('output').value); message('链接已复制。'); }
  catch (_) { $('output').focus(); $('output').select(); message('请长按复制，或按 ⌘C / Ctrl+C。'); }
});
if (location.hash === '#my') showMode('private');
