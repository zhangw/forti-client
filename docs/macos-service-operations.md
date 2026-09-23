# macOS 托管服务操作

实现由三个角色组成：launchd 管理的 root supervisor（`service`）、用户会话代理（`agent`）及 supervisor 的 VPN 工作进程。现有前台 CLI 和 VPN 协议逻辑保留。第一版提供 CLI 控制，不包含菜单栏 App 或 SMAppService 打包。

## 日常操作

`ctl` 是 `forti-client` 的控制子命令，不是独立二进制。安装后的程序位于 `/Library/Application Support/FortiClient/forti-client`。下面的操作不需要 sudo：

```sh
vpn='/Library/Application Support/FortiClient/forti-client'
"$vpn" ctl status
"$vpn" ctl logs
"$vpn" ctl logs --daemon
"$vpn" ctl pause
"$vpn" ctl resume
"$vpn" ctl reconnect
"$vpn" ctl authenticate
```

- `pause` 先保存暂停意图，等待 VPN 进程退出、DNS 清理完成才报告成功；暂停跨服务重启及再次登录保持。
- `resume` 保存连接意图；会话、网络及可信 Wi-Fi 策略仍然有效。
- `reconnect` 重建 VPN；`authenticate` 重建并允许前台打开浏览器。暂停时这两个命令不会隐式恢复。
- `status` / `status --json` 返回 JSON。`Running` 表示进入数据面，仍须用实际网络请求验证连通性。`SuspendedOnTrustedWifi` 是预期的策略暂停。
- `NeedsAuthentication` 或 `ConfigurationError` 不自动循环启动工作进程；查看日志后显式认证/恢复。初次认证等待超时可能需要最多五分钟才进入此状态。
- `WaitingForLoginAgent` 表示指定用户不是控制台用户或登录代理尚未登记。锁屏不等于注销；快速用户切换离开绑定用户时停止 VPN，回来后根据意图恢复。
- 自动认证通过用户代理在后台打开浏览器，不抢前台。当前没有桌面通知，需从 CLI 查看需要登录的状态；菜单栏和通知仍是后续界面工作。

## 安装和切换

以将要使用 VPN 的普通用户构建并准备：

```sh
cargo build --release --locked
python3 scripts/prepare-service.py
```

准备脚本从被 Git 忽略的 `local-run.sh` 读取现有 SAML 网关、端口和可信 Wi-Fi，生成到 `target/service-install`。不将具体网关/SSID 写进已跟踪文件。检查生成的 config、plist 和脚本后，以管理员运行 staged `install-service.sh <已核实的旧进程PID> --smoke`。

安装器针对从现有 `./target/release/forti-client` 前台进程迁移，不是通用升级工具。它先验证文件、部署固定 root 所有路径，然后重新核对旧进程身份、发送 SIGTERM、等待退出，再 bootstrap 两个服务。若旧进程停止失败，不强杀也不启动第二个 VPN。现有托管服务存在时拒绝覆盖升级。

安装位置：

| 文件 | 用途 |
| --- | --- |
| `/Library/Application Support/FortiClient/forti-client` | root 所有的程序 |
| 同目录 `config.json` | 绑定 UID、网关、端口、可信 Wi-Fi；0600 |
| 同目录 `intent.json` | 持久连接/暂停意图；0600 |
| `/Library/LaunchDaemons/com.forti-client.daemon.plist` | system domain 服务 |
| `/Library/LaunchAgents/com.forti-client.agent.plist` | Aqua 会话代理；其他用户不能操作绑定用户的 VPN |
| `/var/run/forti-client/control.sock` | Unix socket，逐请求核验真实 UID |
| `/var/run/forti-client-vpn.lock` | 前台/工作进程共享的全机独占锁 |
| `/Library/Logs/FortiClient/vpn.log`、`.1` | 每份约 5 MiB 上限的轮转工作进程日志 |
| `/Library/Logs/FortiClient/daemon.log`、`.1` | Daemon 启动、控制接口错误、worker 启停及清理日志 |
| `~/Library/Logs/FortiClient/agent.log`、`.1` | 登录用户的 Agent 启动、IPC 失联/恢复及浏览器启动失败日志 |
| `/Library/Logs/FortiClient/smoke-report.json` | 最近一次冒烟结果 |

需要 macOS 管理员授权。若系统后台项目权限被禁用，需要用户在系统设置恢复；程序不绕过该设置。传统 launchd 注册已经实现，SMAppService 的 App 签名/打包没有实现。

## 监督和恢复

Daemon 和 Agent 均设置 KeepAlive，launchd 启动节流为 30 秒。工作进程异常退出后由 Daemon 清理 DNS、等待 30 秒重试；Daemon 自身退出后由 launchd 恢复。Daemon 没有用户会话时仅待命，不连接 VPN。正常服务退出也会被恢复，不能用 kill 表示暂停。

信号停止工作进程最多等待 20 秒，超时强杀，随后幂等清理 DNS。launchd 给予 Daemon 30 秒退出时间。启动/崩溃清理持有独占锁，发生在网关解析之前。路由绑定 utun，冒烟同时检查接口退出后的实际路由消失。

登录代理每秒登记一次；30 秒失联停止 VPN，控制台 UID 变化更快触发停止。会话边界的实际注销、快速切换及合盖行为需要在相应使用场景验证；冒烟不自动注销当前桌面。Agent 能重新连接重启后的 Daemon。KeepAlive 不检测活进程挂死；控制请求超时会报告服务无响应。

## 冒烟和诊断

Daemon、Agent、worker 各自在启动时记录版本、PID/PPID、UID/EUID、工作目录、PATH、代理环境变量的存在性，以及实际 FD 限额和使用量。不记录完整环境变量、控制 token、密码或 cookie。代理变量存在不代表 VPN 会使用代理。

`ctl status --json` 新增以下诊断信息，无需 sudo：

- `resources.daemon/worker/agent`：进程自行采集的 `pid`、`sampled_at`（Unix 秒）、`fd_count`、`limits.soft/hard`；每 60 秒更新一次。`fd_count=null` 或 `limits=null` 表示未知，原因见 `fd_error/limits_error`；已知 `limits` 内的 `soft/hard=null` 表示 unlimited。没有 worker 时，`resources.worker=null`。
- `control.state`：`starting`、`accepting`、`backoff` 或 `restarting`；`accept_errors` 和 `restarts` 是本次 Daemon 生命周期累计值。`last_errno/last_error` 保留最近历史错误，恢复后不清零，以 `state` 判断当前健康状态。

FD 达到软限额 80% 或读取状态从正常变为未知时记录资源状态变化；恢复后也记录。不会调整进程或系统的资源限额。`accept()` 遇到 EMFILE/ENFILE 等资源不足会从 250 ms 退避至最多 5 秒，重复错误最多每 30 秒记录一次；接收任务返回错误或 panic 后，由监督器延迟 1 秒重新启动，保留监听 socket。控制接口完全不可达时，巡检报告连接失败，不能依赖不可达接口返回自己的健康状态。

Daemon/Agent 日志为 0600，每份最多 5 MiB，保留一份 `.1`。文件初始化、写入或轮转失败时尝试限频写入 macOS 系统日志；系统资源耗尽时该兜底也不保证成功。worker 日志继续由 Daemon 轮转。安装升级时应一起重载 Daemon 和 Agent，旧版服务没有资源字段，不能据此判断资源健康。

低成本巡检（替换为实际目标域名）：

```sh
python3 scripts/probe-connectivity.py vpn-app.example.com
```

脚本默认每 60 秒检查 DNS、每个唯一 IPv4 地址的路由和 TCP、控制状态及资源快照。不需要 sudo，但运行环境必须允许本地网络及路由查询。首次、异常变化、恢复或 Daemon/worker PID 变化时输出 JSON；相同异常不重复输出。FD 达到 80%、快照超过 180 秒、采集失败或旧服务缺少字段都会明确报告。`dns_ok`、`route_ok`、`tcp_ok`、`service_ok` 分别表示各层结果，`connectivity_ok` 汇总前三项，`ok` 是最终综合结果。TCP 成功不代表 TLS、HTTP 或页面依赖正常。DNS 解析由系统 resolver 负责，耗时超出间隔时不会并发堆积新一轮。

可重复使用 `--target HOST:PORT=INTERFACE` 检查多个目标；`INTERFACE` 可为任意 `utunN` 对应的 `utun`、精确接口名或不检查接口的 `any`。本机专用目标也可放在 Git 忽略的 `probe-targets.json`，由准备脚本复制到 staging。对已安装的服务，仅部署巡检文件，不需要替换 FortiClient 或重启 VPN：

```sh
python3 scripts/prepare-service.py
sudo target/service-install/install-probe.sh
/usr/bin/python3 "/Library/Application Support/FortiClient/probe-connectivity.py" \
  --targets-file "/Library/Application Support/FortiClient/probe-targets.json" --count 1
```

`install-probe.sh` 只原子替换 root 所有的巡检脚本和非敏感目标配置，不修改 VPN 配置、连接意图或 launchd 服务。相关回归检查：`cargo test --locked --lib` 和 `python3 -m unittest discover -s scripts -p 'test_probe_connectivity.py'`。控制接口故障测试通过注入错误模拟 FD 耗尽和任务 panic，不改变系统 FD 上限，不接触已安装 VPN。

`sudo /usr/bin/python3 scripts/smoke-service.py` 会短暂断开 VPN、故意 SIGKILL 托管工作进程和 Daemon。仅在允许中断时运行。它验证：

1. launchd 服务、用户代理及真实 VPN DNS 查询（内网 DNS 路由必须走 utun）。
2. 暂停后 DNS key 和原接口路由消失。
3. 暂停状态下 Daemon 崩溃重启仍保持暂停。
4. 恢复连接、工作进程崩溃后的清理和自动重连。
5. Daemon 崩溃后无孤儿工作进程，并恢复连通性。

测试最后保持连接意图；失败结果会写报告并尝试恢复连接意图，不声称网络已经恢复。测试依赖网关下发可用的私网 DNS；可信 Wi-Fi 场景不应为通过测试而绕过策略。

```sh
launchctl print gui/$(id -u)/com.forti-client.agent
sudo launchctl print system/com.forti-client.daemon
cat /Library/Logs/FortiClient/smoke-report.json
```

首次安装失败时先检查旧进程是否还在、两个 launchd 标签是否加载，再决定恢复；不要直接再运行第二个前台客户端。当前版本之前的 CLI 不认识独占锁，迁移必须核实其已停止。构建前保留的旧二进制位于 `target/service-rollback/forti-client`，仅用于必要的人工回退。

## 停用和卸载

先执行 `forti-client ctl pause` 并确认成功，再由管理员 bootout Agent 和 Daemon。随后移除两份 plist 及安装目录即可停止以后登录自启；日志可按需保留。不要删除 `/var/run/forti-client-vpn.lock` 来解除正在持有的锁。重新启用使用 bootstrap，并通过 `forti-client ctl resume` 明确恢复连接。

第一版服务只支持 SAML。原有密码/OTP 模式继续在前台 CLI 使用，不会向后台进程传递终端输入。没有持久化 VPN cookie、密码或 OTP。
