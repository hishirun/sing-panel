# panel.example.com 域名部署

2026-10-11：A 记录 203.0.113.10，Cloudflare proxied=true。

Nginx 监听 80，反代 127.0.0.1:18889。源站不安装证书，Cloudflare 到源站为 HTTP；浏览器到 Cloudflare 为 HTTPS。未改整个 zone 的 SSL 设置，既有 443 服务不修改。HTTP 访客自动转 HTTPS。

站点仅允许 Cloudflare 官方 IPv4/IPv6 网段与回环访问；默认虚拟主机拒绝未知 Host。关闭访问日志，session cookie 增加 Secure。网段配置 /etc/nginx/snippets/sing-panel-cf-allow.conf 从 Cloudflare 官方 ips-v4 / ips-v6 获取。站点配置 /etc/nginx/sites-available/sing-panel。

面板 public_url=https://panel.example.com。原密码、用户和节点保留。没有 Tunnel 服务，临时 cloudflared 已卸载。

验证公网登录页、样式、健康检查、分享页和三种订阅均成功；JSON 可解析，面板 Cache-Control 为 no-store。

Token 未存入仓库或服务器，操作后的本地临时 Token 文件已清理。

## 可配置入口路径

系统设置 → 访问路径可设置管理前缀和分享前缀，保存立即生效。管理前缀 / 表示根目录，分享默认 /s；自定义前缀限单段 ASCII 字母、数字、短横线和下划线，3–64 位。冲突和保留路径被拒绝。旧入口返回 404，改变分享前缀后需重新分发订阅。随机临时路径不自动到期。静态资源与 /health 保持公共路径。路径不代替管理员认证或用户订阅令牌。

管理路由、表单、重定向、分享链接与二维码统一使用当前前缀。settings 数据库中 admin_path / share_path 可用于管理员 SSH 恢复入口。部署前代码与数据库备份位于 /opt/sing-panel/backups/before-entry-paths-20261011.*。
