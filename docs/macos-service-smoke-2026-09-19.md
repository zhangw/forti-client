# macOS 托管服务冒烟记录

日期：2026-09-19。本机 macOS 27.2。实际安装并测试，不是模拟结果。

原始报告：`/Library/Logs/FortiClient/smoke-report.json`。

## 验证结果

| 检查 | 结果 |
| --- | --- |
| launchd 启动、用户代理认证及实际内网 DNS 查询 | 通过 |
| 暂停后清除 VPN DNS 及旧接口路由 | 通过 |
| Daemon 被 SIGKILL 后重启仍保持暂停 | 通过 |
| 恢复连接及内网 DNS 查询 | 通过 |
| 工作进程被 SIGKILL 后先清理 DNS 再退避 | 通过 |
| 工作进程自动重启、重新认证及连通性恢复 | 通过 |
| Daemon 被 SIGKILL 后由 launchd 恢复，无遗留旧工作进程 | 通过 |
| 测试结束时保持连接 | 通过 |

另已核对：安装后的二进制 SHA-256 与验证过的 staged release 一致；二进制和安装目录 root 所有且不可由普通用户写入，config/intent 为 0600，plist 为 0644；普通用户伪造工作进程状态事件被控制接口拒绝。

Rust 全套测试 183 项通过；新增服务测试覆盖意图持久化及损坏处理、独占锁、请求 framing/大小限制、协议字段和 UID 验证。严格 Clippy、release 构建、安装脚本语法和 plist 校验通过。

服务：`system/com.forti-client.daemon`；登录代理：`gui/501/com.forti-client.agent`。工作进程由 Daemon 管理；Daemon 和 Agent 由 launchd 管理。旧前台 VPN 已正常退出。测试中的真实网络请求为通过 utun 向 VPN 下发的私网 DNS 查询网关域名；不能据此声称所有内网应用均已验证。

## 验证边界

未为测试注销当前桌面或重启整机；下次真实登录自启依赖已安装的 LaunchAgent/LaunchDaemon 配置，尚无实际重新登录证据。锁屏/合盖、快速用户切换、后台权限被用户禁用、MFA 交互和日志达到轮转阈值未在本次冒烟触发。菜单栏及桌面通知未实现，当前通过 CLI 控制。

源码改动仍留在工作区，未提交。日常命令见 [操作说明](macos-service-operations.md)。
