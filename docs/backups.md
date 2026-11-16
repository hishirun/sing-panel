# 自动备份与恢复

在“系统设置 → 本机自动备份”配置计划、立即创建备份及下载历史归档。备份保存在主面板所在机器，路径为 `$PANEL_DATA/backups/automatic/`；不会自动上传其他服务器或云存储。

## 备份计划

默认开启，每 24 小时备份一次，保留最近 7 份。可选 6／12／24 小时间隔，保留 1–30 份；后台约每分钟检查是否到期。没有历史成功记录时会在服务启动后创建首份备份。关闭自动计划后仍可手动“立即备份”。

成功归档后清理超过保留数量的旧归档；页面显示最近成功时间和失败提示。文件名形如 `panel-YYYYMMDDTHHMMSS-xxxxxxxx.tar.gz`，时间部分为 UTC。归档使用私有文件权限，下载要求管理员登录。

数据库通过 SQLite 在线 backup API 生成一致快照，创建备份时无需停止代理。手工复制整个数据目录与恢复归档仍需先停止主面板。

## 内容与边界

| 内容 | 自动归档 |
| --- | --- |
| `panel.db`：节点、用户、订阅令牌、分流、服务器、计数及面板设置 | 包含在线快照 |
| `auth.json`：管理员认证与会话密钥 | 文件存在时包含 |
| `$PANEL_DATA/tls/` 下的普通证书／私钥文件 | 包含，跳过符号链接及单个超过 8 MiB 的文件 |
| `.env`、`/etc/sing-panel.env`、systemd／Nginx 配置 | 不包含 |
| 主面板代码、Python venv、sing-box、`agent-cores` 安装产物 | 不包含 |
| 数据目录以外的 TLS 文件、符号链接指向的文件 | 不包含 |
| 远端 Agent 的身份与流量队列、远端系统配置 | 不包含 |

归档包含可用的私有连接资料，需要私密保管。下载一份到其他受控存储，才能覆盖主面板磁盘丢失的情况。只下载“运行与维护 → 下载数据库备份”得到的数据库文件，不等于这里的完整归档，它不包含 `auth.json` 和 TLS 文件。

## 人工恢复

当前没有浏览器覆盖导入功能。恢复会回到归档时的用户、额度、路由和凭据状态；归档之后的配置修改及部分用量可能无法恢复。需要保留当前目录，以便失败时回退。

1. 准备对应版本的代码、Python 环境与统计版核心；另外保存或恢复服务环境、Nginx 配置、安装产物及归档外的证书文件。
2. 选择自己创建并信任的备份，先查看归档内容；它应仅包含 `panel.db`、可选 `auth.json` 和 `tls/` 文件。
3. 停止主面板，保留旧数据目录，将归档解压到正确的 `PANEL_DATA`，恢复服务用户所有权。
4. 启动主面板，使用归档中的管理员密码登录，检查公开地址、管理入口、分享入口、服务器与节点配置。
5. 查看 Agent 心跳、配置同步和用户用量；如果归档中的 Agent 凭据与远端现有身份不一致，使用**同一条服务器记录**重新生成接入命令并在对应机器执行。

以下以仓库的原生 systemd 部署为例：数据目录 `/opt/sing-panel/data`，服务用户 `singpanel`。先把占位备份路径替换成实际文件；Docker 或自定义部署要使用自己的服务停止方式、数据卷路径和 UID。

```sh
panel_restore_source=/root/panel-YYYYMMDDTHHMMSS-xxxxxxxx.tar.gz
tar -tzf "$panel_restore_source"

sudo systemctl stop sing-panel
panel_restore_saved="/opt/sing-panel/data.before-restore-$(date -u +%Y%m%dT%H%M%S)"
sudo mv /opt/sing-panel/data "$panel_restore_saved"
sudo install -d -o singpanel -g singpanel -m 0700 /opt/sing-panel/data
sudo tar --no-same-owner -xzf "$panel_restore_source" -C /opt/sing-panel/data
sudo chown -R singpanel:singpanel /opt/sing-panel/data
sudo chmod 0700 /opt/sing-panel/data
sudo systemctl start sing-panel
sudo systemctl status sing-panel --no-pager
```

若归档没有 `auth.json`，需要从受控的原目录恢复正确文件，或按部署流程运行 `panel.setup` 建立管理员认证；服务不会以默认密码启动。外部 TLS 文件仍需恢复到节点配置引用的路径。

恢复期间主控断联超过 90 秒，远端 Agent 会按租约暂停核心；恢复连接后根据归档中的最新有效状态重新同步。不要同时启动旧主控和恢复后的副本来管理同一批 Agent。先确认恢复成功，再按自己的保留策略处理旧数据目录。

## 恢复旧数据库后的 Agent 队列处理

恢复旧数据库可能同时回滚节点和已下发的统计授权。若 Agent 已缓存备份之后新增节点的流量，主控会拒绝这些未知身份，日志出现重复 `1008` 关闭或“Agent 不得上报其他服务器的流量”。重新生成接入码不会自动清空旧队列。

确认主控已恢复到所需快照后，可以在受影响的 Agent 机器上执行以下恢复步骤。它先保留原运行状态，再让 Agent 领取恢复后的配置；尚未上报的旧队列不会自动计入恢复后的数据库。此操作会中断该 Agent 的代理连接。

```sh
sudo systemctl stop sing-panel-agent
agent_recovery_saved="/var/lib/sing-panel-agent/recovery-$(date -u +%Y%m%dT%H%M%S)"
sudo install -d -m 0700 "$agent_recovery_saved"
for agent_recovery_file in runtime.json sing-box.json candidate.json reports.sqlite reports.sqlite-wal reports.sqlite-shm; do
    if sudo test -e "/var/lib/sing-panel-agent/$agent_recovery_file"; then
        sudo mv "/var/lib/sing-panel-agent/$agent_recovery_file" "$agent_recovery_saved/"
    fi
done
sudo systemctl start sing-panel-agent
```

这会保留 `config.json` 中的机器身份。如果恢复的数据库里连原服务器记录也不存在，应先在主控重新添加服务器；在备份 Agent 状态后，将原 `config.json` 也移入上述私有恢复目录，再执行新服务器的接入命令。不要直接把另一台机器的身份文件复制过来。旧目录含凭据和未上报计数，应保留到核对完恢复结果后再由管理员处理。
