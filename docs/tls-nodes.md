# Hysteria2 / AnyTLS

支持 sing-box 1.14.3；Hysteria2 需要 `with_quic` 编译选项。这些协议与其他节点共用所属机器的核心，以及用户额度、到期和周期重置规则。每用户密码来自用户的节点连接密码，统计名称为 `node_id:user_id`。无有效授权用户时不开放入站。

## 配置页面

- 通用：随机端口、监听 IP、可选客户端连接地址、分组、备注。
- TLS：SNI、证书链／私钥路径、最低版本、ALPN；保存时检查文件可读性、密钥匹配、过期时间及域名匹配，并执行真实核心 `check`。默认开启客户端证书校验，订阅不含证书私钥或服务端证书路径。
- Hysteria2：服务端／客户端上传下载带宽、忽略客户端带宽、BBR 策略、Salamander／Gecko 混淆、Gecko 包长度、HTTP/3 伪装 URL、初始 QUIC 包长度、路径 MTU 探测。仅显示 QUIC 选项，不显示 TCP 参数。客户端带宽设置写入订阅配置。
- AnyTLS：空闲检查间隔、超时、最低空闲会话数、自定义 padding、TCP 参数。客户端会话参数写入订阅配置。

节点管理按协议展示专属选项：Snell 的共享 PSK 与流量特征、Reality 的握手检测及密钥配置分别设置，不与 TLS 证书节点混用。各客户端导出范围见[客户端订阅](client-subscriptions.md)。

## 证书与连接地址

为节点准备与 SNI 匹配的证书，Hysteria2 开放所选 UDP 端口，AnyTLS 开放所选 TCP 端口。在用户管理中勾选需要授权的节点。节点使用公网 IP 或直连域名；普通 Cloudflare HTTP 代理不能转发这些原始协议连接。

可以使用 Let's Encrypt 公共证书。采用 HTTP-01 验证时，Nginx 的验证目录需与 certbot 的 webroot 一致，例如 `/var/lib/letsencrypt`。域名、证书路径和验证方式由部署环境决定。

仓库提供 [deploy/renew-node-certificate.sh](../deploy/renew-node-certificate.sh)。原生 systemd 部署可将其安装为 `/etc/letsencrypt/renewal-hooks/deploy/sing-panel`，并将证书目录的完整路径写入 root 所有的 `/etc/sing-panel/node-certificate-lineage`，例如 `/etc/letsencrypt/live/panel.example.com`；也可通过 `PANEL_CERT_LINEAGE` 指定。

续期 hook 只读取上述路径文本，不将其作为脚本执行；仅处理匹配的证书。它将证书链与私钥原子更新到 `/opt/sing-panel/data/tls/`，文件由 `singpanel` 所有、权限为 `0600`，随后重启面板；Nginx 正在运行时还会检查配置并重载。启用前应准备目标目录，并核对服务用户、安装路径和证书来源。未配置时，脚本默认使用 `/etc/letsencrypt/live/panel.example.com`，这只是模板示例；新安装必须指定自己的证书目录。

面板重启会短暂中断所属本机节点连接，并在正常停止时采集最后一份流量。远端节点所需的证书材料由主面板校验后随配置下发。续期配置完成后运行 `certbot renew --dry-run` 验证流程。

## 验证

保存节点后检查核心配置与运行状态，再使用受支持客户端通过实际节点访问 HTTPS 目标。确认 TLS 校验开启、目标域名与证书匹配、用户授权正确，并核对上传／下载是否计入对应用户与节点。

仓库测试覆盖 AnyTLS、Hysteria2 无混淆／Salamander／Gecko 的真实 TCP／UDP 转发、计量一致性、用户隔离、停用订阅及证书校验。执行真实协议测试需要按 README 构建的核心和测试环境，不能以静态配置校验代替实际连通性检查。
