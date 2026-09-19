# macOS 托管运行设计

2026-09-19；原始设计方案。首版实现及操作方式见 [托管服务操作](macos-service-operations.md)；本文中的菜单栏、通知及 SMAppService 打包仍为后续设计。

## 结论

采用用户 LaunchAgent + root LaunchDaemon + 本地控制接口。Agent 在登录会话内负责浏览器、通知和会话登记；Daemon 运行现有 VPN 引擎，由 launchd 自动恢复进程。Daemon 可以开机待命，但只有指定用户登录后才连接 VPN。服务运行不等于 VPN 已连接。

本次范围是调查及设计，不部署或中断当前 VPN。保留前台 CLI，不需要重写 PPP 或迁移 NetworkExtension。首版服务模式覆盖当前 SAML 用例，先提供 CLI 控制，再增加菜单栏。

## 当前证据

- `local-run.sh` 通过 `exec sudo env RUST_LOG=info` 运行相对路径的 release 程序，使用 SAML、10443 端口和可信 Wi-Fi 参数。只读进程检查确认 root sudo → root sudo → root forti-client（PID 5039）。
- `src/main.rs` 在初始认证前解析网关域名；初次 DNS/认证失败可直接退出。尚无服务模式、IPC、持久暂停状态。
- `src/auth/mod.rs::saml_browser_command_with_context` 使用 `SUDO_USER` 配合 `sudo -u USER open`，否则直接 `open`。Daemon 缺少可靠的用户 GUI 上下文，不能照搬。
- 密码通过 stdin 输入，OTP 通过 `/dev/tty` 输入；后台服务无法继续使用。SAML 也可能需要重新登录、MFA 或人工处理超时。
- SAML 固定监听 `127.0.0.1:8020`，DNS 使用固定 key `State:/Network/Service/forti-client/DNS`，不适合并发实例。
- `src/reconnect.rs` 已有断线退避、重新认证、睡眠/唤醒、可信 Wi-Fi 和 `WaitingForInteractiveAuth` 等状态；继续由它管理网络重连，launchd 只监督进程。
- 已处理 SIGINT/SIGTERM/SIGHUP，并有 DNS Drop 兜底。但 SIGKILL/abort 不执行 Drop；新进程 `DNS_INSTALLED=false`，现有同步清理函数会跳过上次残留。先解析网关可能被残留 VPN DNS 阻断。
- 日志默认 `/tmp/forti-client.log`，无轮转；不能依赖解析日志实现稳定的状态接口。

## 选型和 launchd 参数

| 方式 | 判断 |
| --- | --- |
| 登录项直接启动脚本 | sudo 需要交互，缺乏完整进程监督 |
| 普通 LaunchAgent 直接运行 VPN | 没有现有网络操作所需 root 权限；Agent 的 UserName 不会提权 |
| 单独 root LaunchDaemon | 有权限及监督，但没有用户登录边界及浏览器会话 |
| Agent + Daemon | 推荐，分别解决交互与特权操作 |

内部安装可一次性由管理员部署传统 plist；发行 App 时使用 macOS 13+ SMAppService 注册 bundle 中的服务，并展示系统授权状态。用户禁用后台权限后不能绕过。签名、打包和支持的系统版本需要独立验证。本机 `sw_vers` 报告 macOS 27.2，不代表其他版本兼容性已经验证。

Daemon 计划参数：`Label=com.forti-client.daemon`，绝对路径 `ProgramArguments`，`KeepAlive=true`，`ThrottleInterval=30`，`ExitTimeOut=30`，`Umask=63`（八进制 077）。程序保持前台事件循环，不 fork、不套 sudo。二进制、配置、plist 及父目录由 root 控制，不能从用户可写的 Desktop/Git worktree 启动 root 服务。显式设置受控 PATH，系统命令采用绝对路径。

Agent：`Label=com.forti-client.agent`，`LimitLoadToSessionType=Aqua`，`RunAtLoad=true`，`KeepAlive=true`，`ThrottleInterval=30`；运行在目标用户 GUI domain。Agent 不承担网络特权操作。

选择常驻服务意味着正常退出也会重启；暂停必须修改连接意图，不能退出进程。`SuccessfulExit=false` 不恢复正常退出；仅用 `Crashed=true` 不能覆盖所有非零退出。`NetworkState` 在本机手册中已标为不实现，不用于网络判断。KeepAlive 不检测挂死，状态超时要报告失去响应；自动 watchdog 留作后续需求。

安装后的诊断命令为 `launchctl print gui/<uid>/com.forti-client.agent` 和 `sudo launchctl print system/com.forti-client.daemon`。当前并未安装这些标签。launchctl running 不证明 VPN 可用。卸载顺序为请求断开并确认清理、bootout/注销服务、移除安装文件；kill 不等于关闭自启。

## 生命周期及控制需求

建议默认：单机单隧道，绑定安装时指定用户；登录自动连接；注销断开；锁屏/合盖不等于注销。快速用户切换时临时抑制原用户 VPN，返回后恢复，避免机器级路由影响另一用户。这是设计默认，尚非用户确认的个人偏好。

Daemon 将 `desired=connected|paused` 原子写入 root 所有的 0600 状态文件。首次安装默认 connected，后续读取已有意图；损坏时报告错误，不擅自清除暂停。手动暂停跨崩溃、重启和再次登录保持，直到显式恢复。

连接条件：connected 意图 + 合格登录会话 + 非可信 Wi-Fi + 网络允许。可信 Wi-Fi 仅临时抑制，不修改意图；暂停优先于唤醒、自动重连、重新认证。

Agent 登记要结合系统会话状态，不能把 CLI 请求当作登录证据。建议每 10 秒续租，30 秒失联检查会话并撤销交互资格；确认注销立即清理，无法确认按失联上限断开。睡眠暂停租约计时，唤醒重新核验。真实会话通知和租约组合需实测。Daemon 重启后 Agent 自动重连和重新登记，不能只依赖一次登录事件。UI 退出不清除连接意图。

首版控制通道用 Unix domain socket，目录由 root 管理；用 `getpeereid` 核实 UID，仅允许 root 和指定用户。不能相信消息中的 UID。协议带版本、请求 ID、长度限制；只允许固定命令，不接受任意命令执行或路径。原生 App 后续可采用 XPC 并校验签名。

拟新增接口，当前均未实现：

| 命令 | 语义 |
| --- | --- |
| `forti-client ctl status [--json]` | 服务状态、VPN 状态、暂停原因、最后错误、重试时间、认证需求，不返回秘密 |
| `forti-client ctl pause` | 先持久化暂停，再取消认证/重试并清理；返回清理成功或失败 |
| `forti-client ctl resume` | 持久化连接意图，按会话/网络策略恢复 |
| `forti-client ctl reconnect` | 重建隧道；暂停时要求先恢复 |
| `forti-client ctl authenticate` | 经用户 Agent 前台认证；不隐式解除暂停 |
| `forti-client ctl logs` | 普通用户查看脱敏诊断 |

菜单栏显示：服务未运行、已暂停、可信 Wi-Fi 暂停、等待网络、连接中、已连接、需要登录、清理失败。退出界面、暂停 VPN、关闭自启、卸载是不同操作。通知拒绝后仍可从界面/CLI 查看错误。

## 后台认证

保留现有 SAML attempt 和回调校验，由 Daemon 将受控网关 URL、attempt ID、呈现方式发送给授权 Agent，Agent 在用户 GUI 会话打开浏览器。取消/过期 attempt 不再打开页面或接受迟到结果；认证 URL 不进常规日志。

保留已有自动后台 SSO 尝试意图，包括合盖后的重试；锁屏或不可交互时不强制前台弹窗。需要人时显示持久“需要登录”并合并限频通知，允许主动重试。不能把所有超时都归因为 MFA，应显示实际错误。IdP/浏览器决定后台认证是否成功，不能承诺完全无人值守。

首版服务模式仅支持 SAML；凭证模式明确拒绝并提示使用前台 CLI，不能后台等待 stdin/TTY。后续若支持密码/OTP，通过 challenge/response IPC 和用户 Keychain/交互窗口提供，OTP 不落盘，秘密不进入参数、plist、普通配置或日志。

## 必需改造

1. 全机独占锁，前台及服务均遵守；先锁定再清理或操作网络。8020 不是完整实例锁，不自动杀端口占用者。首次迁移先正常停旧 CLI。
2. 启动后、网关解析前，幂等清除本程序独占 DNS key，不依赖新进程的 `DNS_INSTALLED`；检查 scutil 输出及状态。失败可见且限速重试，不清除其他 VPN 配置。
3. 实测 utun 关闭后的路由及网关旁路路由残留，仅按记录且仍匹配的自有资源清理，不批量删路由。
4. 清理后等待 Agent 登记，按持久意图恢复；cookie 目前只在内存，崩溃后需重新认证，恢复进程不等于恢复连接。
5. 初次连接也进入可取消的服务状态机；网络错误继续退避，配置错误/认证等待保持可见状态，避免退出循环引发反复浏览器弹窗。
6. 整条 SIGTERM 清理设置总时限（建议 20 秒），小于 launchd 的 30 秒强杀时限；实际耗时需验证，初始 DNS/认证也必须可取消。
7. 日志使用受保护目录、大小/保留上限及轮转后重新打开策略；普通用户经受控接口读取。默认禁用 TLS keylog，认证信息脱敏。

## 实施及验收

| 阶段 | 交付 | 验证 |
| --- | --- | --- |
| 服务基础 | 独占锁、启动清理、意图存储、状态机 | 暂停跨重启、初始失败可取消、残留 DNS 不阻断网关解析 |
| 控制及交互 | IPC、CLI、Agent、浏览器代理 | UID/协议验证、Agent 重登记、无 TTY 不挂起、迟到认证拒绝 |
| 系统管理 | 固定安装目录、plist、安装卸载、日志轮转 | plist 校验、真实登录/注销、进程崩溃重启、系统禁用权限行为 |
| 界面 | 菜单栏/通知 | 无终端操作暂停、恢复、认证和诊断 |

实施后需在测试窗口执行：

- 登录单实例、注销清理、快速用户切换、锁屏及合盖/唤醒。
- SIGKILL、非零退出、正常退出分别确认 launchd 恢复；检查 DNS、路由、认证及实际内网访问，而非仅 PID。
- 在连接中、认证中、网络等待、可信 Wi-Fi 状态暂停，验证睡眠/网络变化/服务重启均不解除暂停。
- 失效 SSO、MFA、8020 占用、首次启动无网络、SSID 获取失败，确认状态可见且无无界弹窗。
- 残留 DNS 清理先于域名解析；清理失败不能报告成功。
- 前台与服务争锁、Agent 崩溃、日志轮转、状态写入失败、后台权限禁用及卸载恢复。

本次仅验证源码、真实 root 进程链、本机手册及 Apple 文档；未安装服务、制造崩溃或实测登录和后台 SAML。上述测试是实现后门槛，不是已经通过的结果。仅新增设计文档，不运行无关 Rust 测试。

## 参考依据

- 本机 `man launchd.plist`：UserName、KeepAlive、SuccessfulExit、Crashed、ThrottleInterval、ExitTimeOut、NetworkState。
- [Apple：Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [Apple：Service Management](https://developer.apple.com/documentation/servicemanagement)
- [Apple：SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [Apple：Manage login items and background tasks](https://support.apple.com/en-ph/guide/deployment/depdca572563/web)
