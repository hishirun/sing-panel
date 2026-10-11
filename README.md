# sing-panel

基于 **sing-box 1.14.3** 的单机节点、用户和订阅管理面板。

- 节点管理：Snell v5 / v6、VLESS + Reality，创建、启停、删除。
- 用户管理：多节点授权、共享流量额度、到期停用、手动停用、用量重置。
- 订阅分发：用户专属页面、sing-box JSON、基础原生客户端输出、用量响应头、撤销并重新生成链接。
- 计费：sing-box 用户级上/下行计数，SQLite 原子持久化，UTC 日用量。
- 管理登录：Argon2 密码、会话、CSRF 校验、登录限频。

这是首个可运行版本。当前为单台主机的多入站管理，不包含远程 agent 集群、支付订单、套餐系统或自动迁移旧库。Snell 节点可选独立端口 PSK 兼容模式或共享端口 userkey 模式；Reality 使用共享端口。独立端口按授权用户分配，界面中的端口是分配起点。订阅模板后续迭代；当前附带基本 sing-box JSON、Surge Snell 列表与 Shadowrocket URI 输出，未宣称全部客户端版本兼容。

## 运行（Linux Docker）

需要 Docker Compose、可用的节点端口；无需 privileged、Docker socket 或 root 运行面板。

```sh
cp .env.example .env
# 编辑 .env 中的 PANEL_PUBLIC_HOST，填写客户端连接的公网 IP 或域名。
docker compose build
docker compose run --rm panel python -m panel.setup
docker compose up -d
```

管理端默认仅绑定 `127.0.0.1:18889`。使用 SSH 转发：

```sh
ssh -N -L 18889:127.0.0.1:18889 -p 2323 root@YOUR_SERVER
```

浏览器访问 <http://127.0.0.1:18889>。先创建节点，再创建用户并勾选授权节点，打开用户专属订阅页。

公开订阅需要 HTTPS 反向代理，将目标指向 `127.0.0.1:18889`，并设置 `PANEL_SECURE_COOKIE=1`。管理界面也在同一服务上，应限制来源或另行接入管理网络。不要把明文 HTTP 服务直接开放公网。网络防火墙按需放行节点端口。

`/s/<随机令牌>` 是持有即授权的客户页；`/s/<随机令牌>/sing-box.json` 是订阅。令牌泄漏后在用户操作中撤销并重发。关闭访问日志，避免在日志中存储订阅令牌。历史下载凭据在仅撤销订阅链接时仍有效；停用用户会在下一轮同步时移除认证。

## 本地开发

需要 Python 3.13+ 和带 `with_v2ray_api` 的 sing-box。官方普通预编译包不包含该统计功能。Go 版本须满足上游 go.mod（当前至少 1.25.5）。

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest httpx
go install -tags with_quic,with_utls,with_v2ray_api github.com/sagernet/sing-box/cmd/sing-box@v1.14.3
export SING_BOX="$(go env GOPATH)/bin/sing-box"
export PANEL_PUBLIC_HOST=127.0.0.1
.venv/bin/python -m panel.setup
.venv/bin/uvicorn panel.app:app --host 127.0.0.1 --port 18889 --no-access-log
```

不要启动多个 worker 或使用 reload；面板进程独占其核心、数据库和统计端口。`PANEL_DATA` 默认 `./data`，`PANEL_STATS_PORT` 默认 `19090`。备份整个数据目录前应停止服务；目录含密码哈希、订阅令牌和节点私钥，只能由服务用户访问。备份后恢复整个目录并重启即可。

## 统计语义和边界

每 2 秒使用 V2Ray StatsService 读取 `user>>>id>>>traffic>>>uplink/downlink`，不重置核心计数。数据库在同一事务写入采样基线、用户累计和日汇总；相同采样重复提交不会重复计费。不同节点上的同一用户合并到同一计数。管理进程独占启动核心，每次启动创建独立 epoch，避免新核心的小计数被误当作旧周期。

只统计代理承载的应用层字节，不含 TCP/IP、TLS 等协议开销；与旧 snell-ui 的 iptables 口径不同。不得把两种数据混为同一账单。

配置变化先执行 `sing-box check`；启动失败会尝试恢复上一份可运行配置。配置变化需要重启整个核心，因此所有活动连接会断开。禁用/超额/到期用户从入站用户列表移除；无有效授权用户的入站不监听，避免空用户列表的隐式访问。生效延迟通常是采样间隔加重启时间。

正常停止会采集最后一份统计。核心崩溃、主机断电可能丢失最后一次未采样流量；正常重启也有最终采样与连接关闭间的微小窗口。高带宽用户可在轮询窗口内超过额度。这不是精确到字节的实时硬限额系统。日期和到期点均为 UTC，到期日期表示该日 00:00。

Snell v5 的 QUIC Proxy Mode 不支持；v5 TCP 客户端在 sing-box JSON 中以 `version: 4` 导出，这是上游规定的线协议兼容方式。Snell v6 使用 `version: 6`。独立端口模式使用入站计数映射到用户，共享端口模式直接使用用户计数，两种口径不会重复相加。原生客户端 v5/v6 导出保持实际协议版本。Surge 输出仅包括独立端口 Snell；Shadowrocket 另外输出 VLESS Reality URI，尚需实际客户端验证。Reality 使用 VLESS Vision，需填写有效握手域名。

## 验证

```sh
# 单元测试；真实核心测试自动跳过
.venv/bin/python -m pytest -q
# 包含三协议真实传输、跨用户隔离、超额移除和端口冲突回滚
SING_BOX=/absolute/path/to/sing-box .venv/bin/python -m pytest -q
```

真实 Reality 测试使用 `www.cloudflare.com` 作为握手目标，需要可用网络。集成测试自行启动本地 HTTP 服务，向三种协议分别发送并接收载荷，检查落库字节和用户隔离。

## 上游依据

- [Snell 入站与多用户认证](https://sing-box.sagernet.org/configuration/inbound/snell/)
- [Snell 出站与版本映射](https://sing-box.sagernet.org/configuration/outbound/snell/)
- [V2Ray 用户统计](https://sing-box.sagernet.org/configuration/experimental/v2ray-api/)
- [StatsService 协议](https://github.com/SagerNet/sing-box/blob/v1.14.3/experimental/v2rayapi/stats.proto)

此项目独立实现；现有 snell-ui 仅用于功能与计费口径分析，未包含生产数据库、凭据或原项目源码。

## 原生 systemd 部署

仓库提供 [deploy/sing-panel.service](deploy/sing-panel.service)。约定代码和 Python venv 位于 `/opt/sing-panel`，统计版二进制位于 `/opt/sing-panel/sing-box`，服务用户为 `singpanel`。先创建该用户及其拥有的 `data` 目录，运行 `panel.setup`，将 `PANEL_PUBLIC_HOST` 写入 `/etc/sing-panel.env`，再安装并启动 unit。服务仅监听本机 18889；统计 API 仅监听本机 19090。停止服务时先通知主进程完成最后一次采样，再终止子进程。
