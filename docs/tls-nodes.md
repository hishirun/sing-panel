# Hysteria2 / AnyTLS

新机器使用自己的证书 lineage：将完整目录路径写入 root 所有的 `/etc/sing-panel/node-certificate-lineage`，例如 `/etc/letsencrypt/live/panel.example.com`。续期 hook 只读取该文本，不将其作为脚本执行；只处理匹配的证书，原子更新节点证书副本后重启面板，并在 Nginx 运行时校验配置、重载证书。未配置该文件时保留旧部署的默认 lineage。

支持 sing-box 1.14.3；Hysteria2 需要 with_quic 编译选项。新协议与现有节点共用一个核心、用户额度、到期和周期重置规则。每用户密码来自用户的节点密码，统计名称为 node_id:user_id。无有效授权用户时不开放入站。

## 配置页面

- 通用：随机端口、监听 IP、可选客户端连接地址、分组、备注。
- TLS：SNI、证书链/私钥路径、最低版本、ALPN；保存检查可读性、密钥匹配、过期、域名匹配，并执行真实核心 check。默认开启客户端证书校验，订阅不含证书私钥或服务端证书路径。
- Hysteria2：服务端/客户端上传下载带宽、忽略客户端带宽、BBR 策略、Salamander/Gecko 混淆、Gecko 包长度、HTTP/3 伪装 URL、初始 QUIC 包长度、路径 MTU 探测。仅显示 QUIC 选项，不显示 TCP 参数。客户端带宽设置写入 sing-box 配置。
- AnyTLS：空闲检查间隔、超时、最低空闲会话数、自定义 padding、TCP 参数。客户端会话参数写入 sing-box 配置。
- Snell：仅共享模式显示节点 PSK，仅 unsafe-raw 模式显示确认；关闭 Keep Alive 时收起时间项。
- Reality：保留握手检测、SNI、指纹、Flow、ALPN、密钥和 Short ID 专属选项。

sing-box JSON 支持全部协议。Shadowrocket URI 导出 AnyTLS/Hysteria2（Gecko 除外）；Surge 导出目前仍仅包含兼容 Snell，不把未适配协议写入配置。

## 部署示例

例如 Hysteria2 使用 UDP 10443、AnyTLS 使用 TCP 10444；将连接地址 `203.0.113.10` 和 SNI `panel.example.com` 替换为自己的地址。Hysteria2 可使用 Salamander，混淆密码由服务端随机生成，只通过授权订阅分发。在用户管理中勾选需要授权的节点。

使用 Let's Encrypt 公共证书，webroot 为 /var/lib/letsencrypt，CF 代理的 HTTP-01 验证目录由 Nginx 直接提供。节点直连 IP，不走小黄云。原网站代理方式和已有 443 服务不变。

证书在 /etc/letsencrypt/live/panel.example.com，由 certbot.timer 续期。数据目录 /opt/sing-panel/data/tls 下的证书副本由 singpanel 所有、权限 0600。deploy/renew-node-certificate.sh 对应 /etc/letsencrypt/renewal-hooks/deploy/sing-panel，续期后原子更新副本并重启面板，保留停机前计量。certbot renew --dry-run 成功。

## 验证

67 项测试通过；新协议测试覆盖 AnyTLS、Hysteria2 无混淆/Salamander/Gecko 的真实 TCP/UDP 转发、UDP 字节精确计量、用户与节点总量一致、用户隔离、停用订阅、配置页面校验、证书不匹配拒绝，以及用户端重置日期。

两个正式节点均从本机通过公网代理请求成功，出口为服务器 IP，TLS 校验开启。数据与配置备份：/opt/sing-panel/backups/before-hy2-anytls-20261103.*。
