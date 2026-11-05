# WWMM 公开转换与私有预设

公开访问 `https://sc.wwmm.date` 使用自己的订阅与规则；私有入口为页面中的“我的预设”，也可收藏 `https://sc.wwmm.date/#my`。

节点只在 Sub-Store 管理，业务分流只在 GitHub 共用 INI 管理。私有证书、插件和源订阅地址保存在服务器 `/opt/sub/private`，不进入 GitHub、网页静态目录或公共转换容器。

## 六个用途池

| Sub-Store 内部名称 | 显示名称 | 用途标记 | 默认来源与筛选 |
| --- | --- | --- | --- |
| wm-balance | WM 均衡 | `[WM]` | 全部 WWMM，加 69YUN 香港 |
| daily-main | 日常主用 | `[DAILY]` | BW、69YUN |
| ai-primary | AI 优先 | `[AI]` | 全部 WWMM，加 69YUN 日本 |
| ai-backup | AI 后备 | `[AI-BACKUP]` | MESL |
| last-resort | 最后备用 | `[BACKUP]` | 良心云 |
| cathy | Cathy 专用 | `[CATHY]` | Gary02 |

当前五条源订阅均已加入“倍率上限 2x（排除 >2x）”操作，因此单独订阅和所有组合都只保留不超过 2 倍的节点；未标倍率的节点保留。新增源订阅时，在“节点操作”中沿用这一过滤，规则定义在 `multiplier-filter.json`。`apply_multiplier_filter.py` 会先备份，再为全部源订阅幂等添加该操作，不改变其他节点操作。

在 Sub-Store 的组合订阅中调整成员、筛选和顺序即可换机场。保留上述组合内部名称及最后的“用途标记”重命名操作。国旗可以保留；同一物理节点出现在多个池时会拥有不同用途名称，连接信息保持不变。

通过 API 创建的每条操作都必须带有不同的 `id`，这是 Sub-Store 前端读取、编辑和保存参数的键；只有 `type` 和 `args` 时，后端可能正常导出，但界面会显示空白并可能在保存时覆盖参数。两个配置脚本均会补齐 ID，并保留已有有效 ID。

`setup_substore.py` 在创建组合前备份完整订阅和组合；只创建缺失的组合，不覆盖已有组合。首次配置需要设置 `SUBSTORE_ACCESS_FILE` 指向服务器外的私有 JSON 凭据文件，并显式指定 `--backup-dir`。不要把凭据文件或备份提交到仓库。

## 服务器文件

| 路径 | 内容 |
| --- | --- |
| `/opt/sub/private/settings.json` | 私有预设密钥、三个客户端各自的只读下载密钥、内部转换密钥 |
| `/opt/sub/private/loon-base.conf` | Loon General、Plugin、Script、MITM 等个人设置 |
| `/opt/sub/private/clash-base.yaml` | Clash 基础设置 |
| `/opt/sub/private/egern/base.yaml` | Egern DNS、模块、Script、MITM 和 Smart 偏好；仅管理密钥可通过网页编辑 |
| `/opt/sub/private/loon.ini`、`clash.ini` | 六条组合地址、共用 INI 地址与客户端参数 |
| `/opt/sub/public` | 公共转换使用的无个人证书基础模板 |
| `/opt/sub/wwmm-compose.yml` | 新服务的持久化部署配置 |
| `/opt/sub/backups` | 原部署、Sub-Store 和切换前配置备份 |

私有目录和文件归属 `10001:10001`，目录权限 `700`，文件权限 `600`。使用会替换文件的编辑器时，应保持原归属和权限。私有模板中只维护个人设置，节点、策略组和业务规则由共用 INI 生成。保留同一份 `ca-p12` 和 `ca-passphrase`，更新完整配置时才能沿用设备已安装的证书。

修改模板后下次获取配置生效；修改转换器偏好需要重启对应容器。远程 INI 的缓存为 60 秒。Loon 远程规则、插件资源更新和整份主配置的重新导入是不同操作，服务器不会替设备安装或信任新证书。

## 构建与启动

GitHub Actions 的 **WWMM Build and Verify** 会运行接口与导出回归检查，并构建两个镜像。产物 `wwmm-images-<commit>` 中的 `wwmm-images.tar.gz` 可在服务器通过 `docker load -i` 导入，避免在小内存 VPS 上编译。旧的多平台发布流程改为手动触发，不再尝试推送上游作者的 Docker Hub 仓库。

```sh
docker load -i wwmm-images.tar.gz
cd /opt/sub
docker compose -f wwmm-compose.yml up -d
```

首次部署必须先配置私有文件。`settings.json` 的 `admin_key` 为私有预设入口密钥（至少 12 字符）；`tokens.loon`、`tokens.clash`、`tokens.egern` 使用分别生成的随机长密钥（至少 32 字符），`backend_token` 只供服务内部调用；两份档案的 `profile_token` 使用内部密钥。重置某个客户端下载密钥只需修改 `settings.json` 对应 `tokens` 字段，旧链接立即失效，不需要更换内部密钥。

公网只反向代理 `127.0.0.1:18082`。公共和私有转换器没有宿主端口、没有共用网络或数据卷。公开接口仅转发公共转换和规则转换；私有接口固定读取固定的客户端预设，拒绝替换 `url`、`config`、文件路径或重复参数。客户端密钥不能读取管理预设。程序不记录请求 URL，个人配置响应禁止缓存；下载链接本身仍须作为密码保管，不要交给第三方短链服务。

```sh
python3 /opt/sub/source/deploy/verify.py --private-dir /opt/sub/private
```

验证脚本检查公共可用性、私有鉴权、接口隔离、证书保留及三端配置输出，不打印密钥。客户端实际连接、第三方插件执行情况仍需在 Loon / OpenClash / Egern 上验证。

## 客户端差异

共用 INI 按客户端选择规则表示：Clash 保留 GEOSITE，Loon 引用可转换的域名/IP 列表。Loon 端通过规则转换入口过滤不支持的规则类型；中国域名大列表已是兼容的 DOMAIN-SUFFIX 文本，接口直接跳转到其公开源站下载，避免大文件重复中转。GEOSITE 中的少量正则规则无法保证完全等价。TUIC 只保留在 Clash 中，不能导出为 Loon 节点。空用途池使用 REJECT 占位，避免意外变成 DIRECT；需要在 Sub-Store 修复失效订阅。

回退时恢复 Caddy 备份，将 `sc.wwmm.date` 上游切回 `127.0.0.1:18080`；原 `sub`、短链服务和 Redis 保留，不删除原数据。

## Egern

在网页公开转换或“我的预设”中选择 **Egern · Smart**，生成后复制固定下载链接导入 Egern。私有配置包含 `auto_update`，每天从同一受保护地址更新；也可在客户端手动更新。Egern 使用独立 `tokens.egern`，Loon/Clash 的旧链接继续有效。

Egern 支持位于本仓库的生成网关层，C++ 转换器继续解析同一份 INI 并生成 Clash 中间结果；网关再转换节点、策略组和规则。裸 C++ 二进制本身尚未新增 `target=egern`。不要绕过网关发布其内部端口。

Egern 在现有 57 个策略组之外增加“🧠 日常智能”：使用 WM 池的节点，在日常故转中接替原来的 WM 均衡位置；香港→日本→狮城→台湾→美国→其他主用→LX 的顺序保持。原 WM 均衡保留为手动选项。AI 优先、AI 后备在各自池内使用 Smart，AI 外层仍为故转，Gary02 继续只用于专用组。

专用设置里的 `_wwmm` 只供服务器使用，不写入客户端配置：

```yaml
_wwmm:
  smart_groups: ['🔯 AI优先', '🔯 AI后备']
  daily_smart: {'🔯 日常故转': '⚖️ WM均衡'}
  smart_auto_test: true
  priorities:
    'WWMM-': 0.9
    '69YUN': 1
    'MESL': 1
```

`priorities` 是评分系数，小于 1 更偏好，大于 1 降低偏好，0 为优先使用；默认空映射，不偏置。不要把 LX 合入 Smart 池，仅靠大系数不能保证“最后备用”。节点池成员仍在 Sub-Store 调整。改变共用 INI 的分组名时，也需要更新 `_wwmm` 的相应名称。

展开 Egern 设置可编辑整份专用 YAML，保存后再生成。`proxies`、`policy_groups`、`rules`、`auto_update` 由系统生成，编辑器拒绝覆盖。模板保存在独立的可写目录，其他私有文件仍只读挂载。Loon 插件不会自动成为 Egern 模块；请在 `modules` 中维护 Egern 兼容模块。MITM 默认未配置，服务器不会替设备生成、安装或信任证书。

远程规则经 `/egern/rules` 转为 Egern YAML 规则集，保留域名正则；GEOSITE 和非国家 GEOIP 转换为对应的 MetaCubeX 远程列表，国家 GEOIP 原样表达。当前 INI 中 46 条进程名和 1 条源端口规则无法用 Egern 的已文档化规则表达，因此略过，并在生成文件顶部和网页中明确提示。其他未知节点、传输层或规则类型会拒绝生成，避免静默漏节点。

公开和私有的完整 Egern 配置都包含指向各自生成地址的 `auto_update`；节点列表不含该项。公开 Egern 转换支持仅节点列表 `list=true`；完整配置中的常规自动测速组默认使用 Smart，故转与负载均衡保持原类型。公开转换使用仓库内的无私有信息模板，不能读取个人 Egern 设置。
