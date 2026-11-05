"""Qure Color policy icons by Koolson; https://github.com/Koolson/Qure.

Referenced from the author's pinned revision; original artwork remains upstream.
"""
from urllib.parse import quote

QURE_ROOT = 'https://raw.githubusercontent.com/Koolson/Qure/b16b260625f873266f6a6a9b88710132774997b8/IconSet/Color/'
# Specific services precede generic words such as AI, media and manual selection.
ICONS = (
    (('openai', 'chatgpt'), 'ChatGPT'),
    (('gemini',), 'AI'),
    (('claude', 'meta ai', '其他 ai', 'ai优先', 'ai后备', 'ai备用', 'ai故转', 'ai节点选择'), 'Bot'),
    (('cursor', 'emos', '日常智能'), 'Magic'),
    (('youtube',), 'YouTube'),
    (('即时通讯', 'telegram'), 'Telegram'),
    (('github',), 'GitHub'),
    (('speedtest',), 'Speedtest'),
    (('steam',), 'Steam'),
    (('appletv', 'apple tv'), 'Apple_TV_Plus'),
    (('苹果', 'apple'), 'Apple'),
    (('微软', 'microsoft'), 'Microsoft'),
    (('谷歌', 'google'), 'Google'),
    (('tiktok',), 'TikTok_1'),
    (('emby',), 'Emby'),
    (('spotify',), 'Spotify'),
    (('nba',), 'NBA'),
    (('notion',), 'Notion'),
    (('cloudflare',), 'Cloudflare'),
    (('香港', 'hong kong'), 'Hong_Kong'),
    (('日本', 'japan'), 'Japan'),
    (('狮城', '新加坡', 'singapore'), 'Singapore'),
    (('台湾', 'taiwan'), 'Taiwan'),
    (('美国', 'united states'), 'United_States'),
    (('游戏', 'game'), 'Game'),
    (('货币', 'crypto'), 'Cryptocurrency'),
    (('电商', 'shopping'), 'Amazon'),
    (('社交',), 'Global'),
    (('国外流媒体', 'streaming'), 'Streaming'),
    (('国外媒体',), 'ForeignMedia'),
    (('国内媒体',), 'DomesticMedia'),
    (('媒体', 'media'), 'Media'),
    (('直连', 'direct'), 'Direct'),
    (('漏网', 'final'), 'Final'),
    (('cathy',), 'Server'),
    (('均衡', 'balance'), 'Round_Robin'),
    (('手选', 'manual'), 'Static'),
    (('备用', 'backup'), 'Available'),
)
DEFAULTS = {'smart': 'Magic', 'auto_test': 'Auto', 'fallback': 'Auto',
            'load_balance': 'Round_Robin', 'select': 'Proxy'}


def policy_icon(name, kind, original=None, overrides=None):
    """Explicit Egern overrides win, then the shared INI's icon, then defaults."""
    if (overrides or {}).get(name): return overrides[name]
    if original: return original
    lowered = name.casefold()
    file = next((file for words, file in ICONS if any(word in lowered for word in words)), DEFAULTS.get(kind, 'Proxy'))
    return QURE_ROOT + quote(file + '.png', safe='')
