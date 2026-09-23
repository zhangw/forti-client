# FortiClient macOS 原生安装包

## 构建

在 Apple Silicon Mac 上，从仓库根目录运行：

```bash
./scripts/build-macos-pkg.sh
```

脚本会运行 probe Python 回归测试、Rust 测试、Clippy、release 构建，并使用 macOS `pkgbuild`/`productbuild` 生成：

```text
dist/forti-client-<程序版本>-<UTC构建时间>-macos<主版本>-arm64.pkg
dist/forti-client-<程序版本>-<UTC构建时间>-macos<主版本>-arm64.pkg.sha256
```

构建只支持 Apple Silicon，并要求构建机与目标机使用相同的 macOS 主版本。构建不会停止、reload 或修改当前运行中的 VPN。`dist/` 自动只保留最近两个本项目安装包及对应校验文件。

安装包默认未签名，仅适合私下分发。包内不包含 `local-run.sh`、`probe-targets.json`、VPN 网关、可信 Wi-Fi、用户名、设备名、密码、SAML Cookie 或其他目标机环境配置。

## 安装与配置

1. 在目标机登录桌面用户后安装 `.pkg`，提供管理员授权。
2. 安装仅写入程序、launchd plist、服务管理脚本和版本信息；**不会启用、启动或连接 VPN**。
3. 使用管理员权限写入目标机专用配置（示例中的值必须由管理员替换）：

```bash
sudo python3 "/Library/Application Support/FortiClient/configure-service.py" \
  --server vpn.example.com --port 10443 \
  --trusted-wifi TrustedNetwork
```

配置写入 root:wheel、0600 的 `config.json`，不保存密码或 Cookie。

4. 显式启用服务：

```bash
sudo "/Library/Application Support/FortiClient/local-service.sh" enable
```

停用服务：

```bash
sudo "/Library/Application Support/FortiClient/local-service.sh" disable
```

状态检查：

```bash
sudo "/Library/Application Support/FortiClient/local-service.sh" status
```

首次配置和启用前，应先关闭其他 VPN/代理软件并确认目标机网络策略。安装成功不代表 VPN 已连接；需要通过状态和实际网络请求验证。

## 升级边界

当前包只支持全新安装。只要发现任意旧的 FortiClient 文件、配置、intent、plist，或已加载的 daemon/agent，安装器都会拒绝继续；不会覆盖、停止或迁移现有安装。后续升级应单独设计并 review 保留配置、保留连接意图和失败回滚事务。

包安装前如果发现不安全的符号链接或不完整路径，会拒绝继续。探测脚本和 `probe-targets.json` 仍使用现有的独立 staging/deployment 流程，不自动进入通用安装包。
