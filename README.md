# sing-panel

基于 **sing-box 1.14.3** 的节点、用户和订阅管理面板，支持主面板本机及多台 Linux Agent。

用户可见信息、系统网络隔离及部署要求见 [安全说明](docs/security.md)。

- 节点管理：Snell v5 / v6、VLESS + Reality、Hysteria2、AnyTLS、SS / SS2022、Trojan，按服务器创建、启停和授权。
- 服务器管理：WSS 接入、一次性 Linux 安装命令、资源与网卡状态、配置同步、核心启停及 Agent 更新。
- 用户管理：按机器选择节点、跨机器共享流量额度、到期停用、手动停用、用量重置。
- 机器额度：整机主网卡月流量，接收／发送／双向计费，UTC+8 月度重置及超额暂停。
- 订阅分发：用户专属页面、sing-box JSON、基础原生客户端输出、用量响应头、撤销并重新生成链接。
- 计费：sing-box 用户级上/下行计数，SQLite 原子持久化，UTC 日用量。
- 管理登录：Argon2 密码、会话、CSRF 校验、登录限频。
- 本机自动备份：在线数据库快照、面板凭据与数据目录内 TLS 文件，可定时保留并下载。
- 用户自定义分流：管理员授权出口，登录用户面板后管理，默认最多 6 条 GeoSite／GeoIP／域名／IP 规则，草稿与集中发布，跨用户隔离及失败恢复。使用说明见 [分流管理](docs/routing.md#用户自定义分流)。

主面板统一保存用户、节点和分流设置，Agent 运行所属机器的核心；不包含支付订单、主控高可用或已有节点的跨机器自动迁移。Snell 节点可选独立端口 PSK 兼容模式或共享端口 userkey 模式；Reality 使用共享端口。独立端口按授权用户分配，界面中的端口供首位用户使用，其余用户随机分配独立端口。客户端订阅的格式、导入与兼容范围见 [客户端订阅](docs/client-subscriptions.md)。

## 多服务器管理

在主面板的“服务器”页面添加机器，填写客户端连接用的公网 IP 或直连域名；保存后复制安装命令，在目标 Linux 服务器执行。接入码有效期 15 分钟，仅绑定一次；接入成功后，为该机器创建节点并授权用户。主面板本机无需再安装 Agent。

Agent 主动通过 WSS 连接主面板，使用独立系统用户和 `sing-panel-agent.service`，无需开放远程管理端口。主面板须提供 HTTPS 入口、WebSocket 反代和对应架构的统计版核心安装包。断联租约为 90 秒：过期后暂停该 Agent 管理的核心，重新连接并收到有效配置后恢复。

接入条件、安装包准备、状态含义、Agent 更新和机器额度说明见 [多服务器与 Agent](docs/fleet.md)。备份范围与人工恢复步骤见 [自动备份与恢复](docs/backups.md)。

## 开源许可证

面板与 Agent 原创代码采用 [GNU GPL v3.0](LICENSE)（`GPL-3.0-only`）。
sing-box 核心、Surfboard 配置模板和第三方图像保留各自的许可证或权利声明，详见
[第三方声明](THIRD_PARTY_NOTICES.md)。本项目独立维护，不代表上游或客户端官方。

部署文档中的 `panel.example.com`、`203.0.113.10` 等为示例，安装前替换为自己的地址。
不要提交生产数据库、密码、证书私钥、订阅令牌或备份文件。

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
ssh -N -L 18889:127.0.0.1:18889 -p 22 USER@YOUR_SERVER
```

浏览器访问 <http://127.0.0.1:18889>。先创建节点，再创建用户并勾选授权节点，打开用户专属订阅页。

公开订阅需要 HTTPS 反向代理，将目标指向 `127.0.0.1:18889`，并设置 `PANEL_SECURE_COOKIE=1`。管理界面也在同一服务上，应限制来源或另行接入管理网络。不要把明文 HTTP 服务直接开放公网。网络防火墙按需放行节点端口。

管理员使用账号与密码登录，登录表单支持浏览器密码保存与自动填充。旧安装升级后的账号默认为 `admin`，密码保持原值；新安装运行 `python -m panel.setup` 时可指定管理员账号。

`/s/<随机令牌>` 在浏览器中进入受密码保护的用户面板，未设置密码的用户首次访问自行设密；管理员可以随机重置登录密码，立即撤销旧会话。登录密码独立于节点 PSK/UUID，数据库只保存 Argon2 哈希。`/s/<随机令牌>/sing-box.json` 及客户端 UA 自动适配仍以订阅令牌授权，不要求交互式登录。令牌泄漏后在用户操作中撤销并重发。关闭访问日志，避免在日志中存储订阅令牌。历史下载凭据在仅撤销订阅链接时仍有效；停用用户会在下一轮同步时移除认证。

## 本地开发

需要 Python 3.13+ 和按下方脚本构建的 sing-box（包含统计与连接身份扩展）。官方普通预编译包不包含该统计功能。Go 版本须满足上游 go.mod（当前至少 1.25.5）。

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest httpx
./deploy/build-core.sh "$PWD/.venv/bin/sing-box"
export SING_BOX="$PWD/.venv/bin/sing-box"
export PANEL_PUBLIC_HOST=127.0.0.1
.venv/bin/python -m panel.setup
.venv/bin/uvicorn panel.app:app --host 127.0.0.1 --port 18889 --no-access-log
```

不要启动多个 worker 或使用 reload；面板进程独占其核心、数据库、统计端口和 Agent 连接。`PANEL_DATA` 默认 `./data`，`PANEL_STATS_PORT` 默认 `19090`。系统设置中的“本机自动备份”可在线生成一致的 SQLite 快照；直接复制整个数据目录前应停止服务。数据目录含密码哈希、订阅令牌和节点私钥，只能由服务用户访问。恢复范围及操作见 [自动备份与恢复](docs/backups.md)。

## 统计语义和边界

每 2 秒使用 V2Ray StatsService 读取 `user>>>id>>>traffic>>>uplink/downlink`，不重置核心计数。数据库在同一事务写入采样基线、用户累计和日汇总；相同采样重复提交不会重复计费。不同节点上的同一用户合并到同一计数。管理进程独占启动核心，每次启动创建独立 epoch，避免新核心的小计数被误当作旧周期。

远端 Agent 持久化累计采样并通过 WSS 上报；主控按服务器与核心 epoch 隔离基线，提交用量后才确认报告。用户在本机与远端节点之间共享同一额度和有效期。停用、到期或额度用尽后，在线 Agent 在后续同步中移除用户；断联机器受 90 秒租约限制。多台机器并行传输仍可能在采样与同步窗口内超额。

只统计代理承载的应用层字节，不含 TCP/IP、TLS 等协议开销；与系统网卡或防火墙计数的口径不同，不应直接混用。

配置变化先执行 `sing-box check`；启动失败会尝试恢复上一份可运行配置。配置变化需要重启整个核心，因此所有活动连接会断开。禁用/超额/到期用户从入站用户列表移除；无有效授权用户的入站不监听，避免空用户列表的隐式访问。生效延迟通常是采样间隔加重启时间。

正常停止会采集最后一份统计。核心崩溃、主机断电可能丢失最后一次未采样流量；正常重启也有最终采样与连接关闭间的微小窗口。高带宽用户可在轮询窗口内超过额度。这不是精确到字节的实时硬限额系统。用户用量日历、套餐重置与到期点使用 UTC，到期日期表示该日 00:00；**机器月额度单独使用 UTC+8**。

Snell v5 的 QUIC Proxy Mode 不支持；v5 TCP 客户端在 sing-box JSON 中以 `version: 4` 导出，这是上游规定的线协议兼容方式。Snell v6 使用 `version: 6`。独立端口模式使用入站计数映射到用户，共享端口模式直接使用用户计数，两种口径不会重复相加。原生客户端 v5/v6 导出保持实际协议版本。各客户端仅导出其支持的协议组合；SS、SS2022 和 Trojan 的模式、密钥、传输与兼容范围见 [协议配置](docs/protocols.md)。Reality 使用 VLESS Vision，需填写有效握手域名。

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

本项目独立维护；核心补丁、配置模板与第三方资源的来源和许可见[第三方声明](THIRD_PARTY_NOTICES.md)。

## 原生 systemd 部署

仓库提供 [deploy/sing-panel.service](deploy/sing-panel.service)。约定代码和 Python venv 位于 `/opt/sing-panel`，统计版二进制位于 `/opt/sing-panel/sing-box`，服务用户为 `singpanel`。先创建该用户及其拥有的 `data` 目录，运行 `panel.setup`，将 `PANEL_PUBLIC_HOST` 写入 `/etc/sing-panel.env`，再安装并启动 unit。服务仅监听本机 18889；统计 API 仅监听本机 19090。停止服务时先通知主进程完成最后一次采样，再终止子进程。

## 节点高级配置

控制台的“新建节点”和“编辑配置”打开完整设置页；旧节点自动迁移并继承默认值。

- **Snell v6**：`default`（加密 + PSK 派生流量整形）、`unshaped`（加密、不整形）、`unsafe-raw`（无加密，需显式风险确认）。支持共享节点 PSK、客户端连接复用和网络类型。v6 的具体流量特征由核心根据 PSK 派生，不存在任意手工特征模板字段。
- **Snell v5**：HTTP 混淆及客户端 Host；v6 不使用 v5 的混淆选项。
- **SS / SS2022**：独立端口或 AES 系列共享端口、加密方式、自动密钥、TCP/UDP 网络限制；用户流量与其他节点共享额度。
- **个人出口**：用户自带 HTTP(S)、SOCKS5、SS/SS2022，支持批量导入预览与导出备份，所属用户专用；管理员可查看配置、修改和测速。
- **TUIC v5**：TLS 1.3、拥塞控制、认证超时、心跳、原生 UDP / QUIC 流转发，按用户统计。
- **ShadowTLS v3**：一键组合 Shadowsocks；独立用户端口、自动认证、无端口后端、只计解密后流量（TCP）。远端需 Agent 0.2.1+。
- **Trojan**：证书、SNI、TLS 最低版本、ALPN，以及 TCP / WebSocket / gRPC 传输选项。
- **通用监听**：IPv4/IPv6 监听地址、TCP Fast Open、Multipath TCP、Keep Alive 开关与时间。功能仍取决于系统与对端支持。已有授权的独立端口节点不能直接改变端口起点或认证模式，以免悄悄更换用户端口。
- **Reality**：SNI 与握手域名/IP 分开配置，支持握手端口与超时、允许时间差、多个 Short ID、X25519 私钥导入/自动公钥推导/密钥重生成、客户端 uTLS 指纹、Flow、ALPN。服务端只接受该入站的一个 SNI；订阅选择 Short ID 列表的第一项。服务端与导出客户端保持一致。
- **候选 SNI**：`www.cloudflare.com`、`www.microsoft.com`、`www.apple.com`。使用前应从节点所在网络验证 TLS 1.3 与 h2 支持，候选域名不保证持续或各地区可用。编辑页可执行证书校验和 TLS 握手检测，检测不保存节点。

保存前对包含测试用户的完整入站执行 `sing-box check`，即便节点尚无授权用户，也能检查配置。字段和错误提示不会回显导入私钥或 PSK。订阅不会包含服务端私钥；修改密钥、PSK、SNI 等参数后客户端需更新配置。

### 随机端口

新建节点的端口留空时，自动从 20000–65000 中随机选择可用端口；也可以手动填写。端口持久保存，重启不会重新生成。分配会避开面板、统计 API、已有节点/用户端口，并检查系统 TCP/UDP 占用。PSK 兼容模式首位用户使用节点端口，其余用户使用独立随机端口，全部由 sing-box 运行。节点列表可确认重新随机分配整个节点及其用户端口；此操作会断开连接，需要客户端更新订阅。系统其他服务仍可能在检查后抢占端口，核心启动失败时沿用已有回滚机制。

### 订阅分享页

用户专属 `/s/{token}` 页面登录后提供多节点配置、共享额度与到期倒计时、上传/下载与每日记录、配置复制、节点 URI 二维码、分享页/订阅地址二维码，以及个人协议密码自助修改。修改密码需要页面 CSRF，20 秒内限一次，更新该用户的密码类节点凭据及 SS2022 派生密钥，不更改 Reality UUID。停用或到期用户不展示连接凭据；撤销分享链接也使旧二维码入口失效。

管理端“品牌与分享设置”可设置品牌、联系说明、浅色玻璃/深色主题及公开 URL。公开 URL 仅用于生成链接，不会自动配置 DNS、反向代理或公开监听；通过 SSH 本地端口转发访问时，默认分享 URL 仅在相同转发环境可用。二维码在服务端本地生成，不传给第三方。

监控线程每分钟测试配置目标的 TCP 建连，独立于核心统计线程，保留最近一天采样，分享页展示最近 30 次。此延迟是服务器到目标的测量，不是客户端到节点的测量；失败与超过三分钟未更新会标记。分享页只显示目标名称，不显示目标地址。默认目标 Cloudflare/Microsoft/Apple，可改动或留空关闭。

字节级实测与复现脚本见 [流量计量报告](docs/traffic-audit-2026-10-11.md)。


## 管理页面与用户生命周期

- `/`：运行概览；`/servers`：服务器、Agent 与机器额度；`/users`：用户列表及节点授权；`/nodes`：节点列表、复制与批量启停；`/settings`：品牌、公开链接与监控设置；`/system/backups`：自动备份；`/system/status`：本机核心、重启、数据库备份、密码及操作记录。自定义管理路径会统一加在这些路径之前。
- 用户支持名称、分组、备注、UUID/PSK 编辑、多节点授权、批量创建、启停、删除、续费加天数/流量、重置用量、重发订阅、轮换连接凭据、主动断开连接、清理无授权或已耗尽用户。
- 首次使用有效期从第一次非零业务流量开始。固定日期与日历边界均为 UTC；自动续期支持固定天数、每周、每月及次数上限，成功续期会清零本期流量，手动停用保持停用。独立流量周期仅重置用量，不延长有效期；已有采样基线保留，防止重新计费。
- 在线状态、最近 IP、最后在线和断开连接来自各机器受密钥保护的本地 Clash API；主控合并本机连接与 Agent 快照。`core-patches/connection-user.patch` 在连接元数据中补充用户和入站身份，便于共享端口映射。需用 `with_clash_api` 与补丁构建；Docker/CI 已同步。控制接口只监听统计端口 +1（本机默认 19091，Agent 默认 19191），不可对公网开放。
- 同时在线 IP 上限由 Agent 约每 2 秒执行本机检查，主控合并在线快照执行跨机器限制；保留较早建立连接的 IP，关闭新增超额 IP 的连接。每台 Agent 每次最多上报 1000 条连接，截断会影响主控视图完整性。此机制不是握手前或逐包硬限制；IP 数不等于设备数，NAT 下多设备会共用 IP。清空历史后，仍在线的 IP 会再次出现。详细边界见 [在线用户与 IP 数限制](docs/fleet.md#在线用户与-ip-数限制)。
- 外部节点 URI 直接附加到 Shadowrocket URI 订阅；远程 http(s) 订阅需管理员点击刷新，限 5 个地址、单个最多 256 KiB，成功后缓存。暂不转换到 sing-box JSON 或 Surge。停用用户不返回外部节点。
- “运行与维护”的单独数据库下载包含节点/用户凭据，不含管理员认证文件；“本机自动备份”的归档另外包含 `auth.json` 与数据目录内 TLS 文件。人工恢复应停止服务并保留原数据；当前不提供浏览器覆盖导入。修改管理员密码会使其他已有管理会话失效。
