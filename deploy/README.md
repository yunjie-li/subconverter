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

`setup_substore.py` 在创建组合前备份完整订阅和组合；只创建缺失的组合，不覆盖已有组合。首次配置需要设置 `SUBSTORE_ACCESS_FILE` 指向服务器外的私有 JSON 凭据文件，并显式指定 `--backup-dir`。不要把凭据文件或备份提交到仓库。

## 服务器文件

| 路径 | 内容 |
| --- | --- |
| `/opt/sub/private/settings.json` | 私有预设密钥、两端只读下载密钥、内部转换密钥 |
| `/opt/sub/private/loon-base.conf` | Loon General、Plugin、Script、MITM 等个人设置 |
| `/opt/sub/private/clash-base.yaml` | Clash 基础设置 |
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

首次部署必须先配置私有文件。`settings.json` 的 `admin_key` 和 `tokens.loon`、`tokens.clash` 使用分别生成的随机长密钥（至少 32 字符），`backend_token` 只供服务内部调用；两份档案的 `profile_token` 使用内部密钥。重置某个客户端下载密钥只需修改 `settings.json` 对应 `tokens` 字段，旧链接立即失效，不需要更换内部密钥。

公网只反向代理 `127.0.0.1:18082`。公共和私有转换器没有宿主端口、没有共用网络或数据卷。公开接口仅转发公共转换和规则转换；私有接口固定读取两份预设，拒绝替换 `url`、`config`、文件路径或重复参数。客户端密钥不能读取管理预设。程序不记录请求 URL，个人配置响应禁止缓存；下载链接本身仍须作为密码保管，不要交给第三方短链服务。

```sh
python3 /opt/sub/source/deploy/verify.py --private-dir /opt/sub/private
```

验证脚本检查公共可用性、私有鉴权、接口隔离、证书保留及两端配置输出，不打印密钥。客户端实际连接、第三方插件执行情况仍需在 Loon / OpenClash 上验证。

## 客户端差异

共用 INI 按客户端选择规则表示：Clash 保留 GEOSITE，Loon 引用可转换的域名/IP 列表。Loon 端通过规则转换入口过滤不支持的规则类型；中国域名大列表已是兼容的 DOMAIN-SUFFIX 文本，接口直接跳转到其公开源站下载，避免大文件重复中转。GEOSITE 中的少量正则规则无法保证完全等价。TUIC 只保留在 Clash 中，不能导出为 Loon 节点。空用途池使用 REJECT 占位，避免意外变成 DIRECT；需要在 Sub-Store 修复失效订阅。

回退时恢复 Caddy 备份，将 `sc.wwmm.date` 上游切回 `127.0.0.1:18080`；原 `sub`、短链服务和 Redis 保留，不删除原数据。
