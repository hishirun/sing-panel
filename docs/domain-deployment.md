# 域名与反向代理

示例使用 `panel.example.com`，安装前替换为自己的域名。将 HTTPS 反向代理指向面板的 `127.0.0.1:18889`，并在面板系统设置中将 `public_url` 设为 `https://panel.example.com`。公开地址只用于生成链接，不会自动配置 DNS 或证书。

## Cloudflare 代理示例

[deploy/nginx-cloudflare.conf](../deploy/nginx-cloudflare.conf) 适用于 Cloudflare 代理的域名，包含 WebSocket 升级、HTTP 访问跳转 HTTPS、关闭访问日志及 Secure 会话 Cookie 设置。部署时：

1. 为域名创建指向源站的 A／AAAA 记录并开启代理。
2. 将示例中的域名替换为实际域名；`map` 指令放在 Nginx 的 `http` 上下文中。
3. 从 Cloudflare 官方 IPv4／IPv6 网段生成 `/etc/nginx/snippets/sing-panel-cf-allow.conf`，仅允许这些来源和回环访问。默认虚拟主机拒绝未知 Host。
4. 设置 `PANEL_SECURE_COOKIE=1`，检查 Nginx 配置后启用站点。

该示例监听源站 80 端口，Cloudflare 到源站使用 HTTP，浏览器到 Cloudflare 使用 HTTPS。它不提供回源 TLS；若采用 HTTPS 回源，应另外配置源站证书和对应监听。代理请求头只应信任受控反代来源，详细边界见[安全说明](security.md)。

Nginx 将 `/.well-known/acme-challenge/` 映射到 `/var/lib/letsencrypt`，可用于节点证书的 HTTP-01 验证。普通 Cloudflare HTTP 代理不承载 Snell、Reality、Hysteria2 或 AnyTLS 的原始节点连接；节点应配置公网 IP 或直连域名。多服务器接入需要保留 `/agent/` 的 WebSocket 转发，见[多服务器与 Agent](fleet.md)。

部署后检查登录页、静态资源、`/health`、用户面板，以及实际使用的客户端订阅格式。确认 HTTPS、登录与退出、WebSocket 连接和 `Cache-Control: no-store` 正常。不要将 DNS API Token、订阅令牌或证书私钥写入公开配置与日志。

## 可配置入口路径

系统设置 → 访问路径可设置管理前缀和分享前缀，保存立即生效。管理前缀 `/` 表示根目录，分享默认 `/s`；自定义前缀限单段 ASCII 字母、数字、短横线和下划线，3–64 位。冲突和保留路径被拒绝。

管理路由、表单、重定向、分享链接与二维码统一使用当前前缀。修改前缀后旧入口返回 404；改变分享前缀后需重新分发订阅。随机生成的路径不会自动到期，静态资源、`/health` 和 `/agent/` 保持固定公共路径。路径不代替管理员认证、用户面板密码或订阅令牌。

忘记入口时，可通过服务器上的数据库 `settings` 表读取 `admin_path` 与 `share_path`。修改设置前按[备份说明](backups.md)保留可恢复快照。

## 用户面板与流量展示

用户面板登录后可查看用量、节点、订阅及个人分流。分享页时间范围支持 24 小时、7 天和 30 天，默认 7 天；柱状图按节点堆叠上传与下载之和，明细表随范围切换。缺失时间桶补零，小流量按 B／KiB／MiB 展示；图表支持悬停和键盘聚焦查看数值。

小时视图包含当前 UTC 小时与前 23 小时，日视图按 UTC 日历日统计。节点日、小时差分与用户总量在同一事务写入，采样基线用于防止重复记账。历史未归属用量单独显示，不按比例推算到节点，也不估算启用小时统计之前的数据。节点历史累计不随当前套餐额度重置而清零。

创建或编辑用户时，“流量套餐”支持一次性、每天、每周、每月及自定义间隔。周期套餐必须填写大于 0 的额度；一次性额度为 0 时表示不限量。每日套餐在下一 UTC 零点重置本期用量，其他周期按各自规则计算，不累计剩余额度，也不延长有效期。自动续期是独立设置。
