# Shadowsocks、Trojan、TUIC 与 ShadowTLS

节点管理可创建 Shadowsocks（SS / SS2022 合并入口）、Trojan、TUIC v5、ShadowTLS v3 组合节点。所有用户继续共享其原有总额度、到期时间和周期重置规则，用户与节点的每日/每小时用量归入原统计表。无有效授权用户的节点不会监听端口。

## Shadowsocks

支持 aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305。每用户使用独立端口与个人协议密码，端口自动随机分配，移除再授权以外的普通编辑会保留个人端口。可选择 TCP+UDP、仅 TCP 或仅 UDP。采用入站级统计，每个入站标签绑定节点与用户，避免多个用户混算。

## SS2022

支持 AES-128、AES-256 和 ChaCha20 三种 2022 方法。AES 可选共享或独立端口；ChaCha20 使用独立端口。服务器密钥按加密方式自动生成正确长度的 Base64，也可导入或重新生成。个人密钥由用户协议密码、节点 ID 和加密方式通过 HMAC-SHA256 派生，不同用户及节点互相隔离；重置个人协议密码会更新自己的 SS2022 密钥。

共享模式的客户端密码按协议组合为 serverKey:userKey，服务器密钥本身不能替代其他用户的个人密钥。订阅不包含其他用户密钥。独立端口只导出个人密钥。

## Trojan

每用户独立密码，共享监听端口。配置真实证书、私钥路径、SNI、TLS 最低版本和 ALPN；保存时校验证书覆盖域名与有效期。可选 TCP、WebSocket（路径、Host）和 gRPC（服务名）。证书与私钥文件只供服务器使用，客户端默认校验证书。

## 订阅格式

- sing-box、Mihomo、通用 URI：三类节点均可导出，包含对应 WebSocket/gRPC 参数。
- Surge、Surfboard：支持传统 SS、AES 系列 SS2022，以及 Trojan TCP/WebSocket；不导出不支持的 SS2022 ChaCha20 或 Trojan gRPC。
- SS2022 URI 按 SIP002 使用未做 Base64 包裹的加密方式及 URL 转义密钥；传统 SS 使用 Base64URL 用户信息。

共享端口节点按用户统计，独立端口节点按带有用户标识的入站统计，不同时累计两类计数。修改协议参数或密钥后，客户端需要更新订阅。

## SS 统一入口

在 Shadowsocks 表单选择经典 AEAD 或 2022 加密方式，面板自动识别协议。经典 SS、2022 ChaCha20 使用独立端口；AES 2022 可选共享端口。原有 SS/SS2022 节点与订阅继续兼容。已有授权时，切换加密方式可保留独立端口，但更改认证模式需要先撤销授权。

## TUIC v5

使用 UDP 监听端口、真实 TLS 1.3 证书与 h3 ALPN。每用户 UUID + 协议密码认证，共享端口但按 `node_id:user_id` 独立计费。支持 cubic / new_reno / bbr、认证超时、心跳，以及客户端 native / quic UDP 转发模式。0-RTT 固定关闭，避免重放风险。修改用户协议密码、UUID、额度、到期或授权与其他节点一样生效。

## ShadowTLS v3 一键组合

一个面板节点自动生成两层：外层严格 ShadowTLS v3 认证，内层 Shadowsocks。选择 SS 加密方式、TLS 握手域名和端口即可；无需申请本地证书，握手目标须支持 TLS 1.3，保存前可点击检测。默认 www.cloudflare.com，也可填自己验证过的域名。伪装站点的可达性会影响连接。

每用户随机独立端口；外层认证由其个人协议密码和节点 ID 派生，内层 SS2022 密钥另行派生。后端通过核心 detour 注入，不监听 TCP/UDP 端口，不能绕过外层直连。只统计内层解密后的入站计数，外层用户计数不计费。一个授权控制整个组合，停用、到期、额度耗尽或撤销授权时两层一起移除。支持服务器分流和用户自定义分流，统计仍归入同一面板节点。组合仅支持 TCP，不宣称 UDP 转发。

远程服务器需要 Agent 0.2.1+；已接入旧版本的机器须先从服务器管理更新 Agent。Agent 只允许无监听后端用于严格 ShadowTLS v3 的注入目标，其他节点仍要求非特权监听端口。

## 新协议订阅兼容

| 协议 | sing-box | Mihomo | Surge | Surfboard | Shadowrocket |
| --- | --- | --- | --- | --- | --- |
| TUIC v5 | 原生 | 原生 | tuic-v5 | tuic-v5 | TUIC URI |
| ShadowTLS v3 + SS | SS + 隐藏 ShadowTLS detour | SS shadow-tls 插件 | shadow-tls-version=3 | 不导出 | SS URI 的 shadow-tls 参数 |

ShadowTLS 辅助出站不进入节点选择组，不增加订阅节点数。SS2022 ChaCha20 的 Surge 不兼容限制同样适用于组合节点。Surfboard 未声明支持 ShadowTLS，避免输出无法连接的裸 SS 节点。所有客户端配置均在本地生成，不交给第三方转换器；不包含服务器私钥、其他用户或上游出口的密码。实际核心测试覆盖两用户的 TCP/UDP（TUIC）、TCP（ShadowTLS）、逐字节计量、各自出口分流和内网隔离。移动客户端输出按其格式生成，仍应使用支持这些协议的当前版本。

参考：[sing-box TUIC](https://sing-box.sagernet.org/configuration/inbound/tuic/)、[ShadowTLS](https://sing-box.sagernet.org/configuration/inbound/shadowtls/)、[Surge TUIC](https://manual.nssurge.com/policies/tuic.html)、[Surge ShadowTLS](https://manual.nssurge.com/policies/tls.html)、[Mihomo SS](https://wiki.metacubex.one/config/proxies/ss/)、[Surfboard TUIC](https://getsurfboard.com/docs/profile-format/proxy/external-proxy/tuic-v5/)。
