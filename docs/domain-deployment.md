# panel.example.com 域名部署

2026-10-11：A 记录 203.0.113.10，Cloudflare proxied=true。

Nginx 监听 80，反代 127.0.0.1:18889。源站不安装证书，Cloudflare 到源站为 HTTP；浏览器到 Cloudflare 为 HTTPS。未改整个 zone 的 SSL 设置，既有 443 服务不修改。HTTP 访客自动转 HTTPS。

站点仅允许 Cloudflare 官方 IPv4/IPv6 网段与回环访问；默认虚拟主机拒绝未知 Host。关闭访问日志，session cookie 增加 Secure。网段配置 /etc/nginx/snippets/sing-panel-cf-allow.conf 从 Cloudflare 官方 ips-v4 / ips-v6 获取。站点配置 /etc/nginx/sites-available/sing-panel。

面板 public_url=https://panel.example.com。原密码、用户和节点保留。没有 Tunnel 服务，临时 cloudflared 已卸载。

验证公网登录页、样式、健康检查、分享页和三种订阅均成功；JSON 可解析，面板 Cache-Control 为 no-store。

Token 未存入仓库或服务器，操作后的本地临时 Token 文件已清理。
