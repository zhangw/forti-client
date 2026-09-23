#!/bin/bash
# Build an environment-neutral, private FortiClient macOS installer.
set -euo pipefail
umask 077
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo 'Build on an Apple Silicon Mac.' >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/scripts/payload" "$repo_dir/dist"
printf '*\n' > "$repo_dir/dist/.gitignore"
cd "$repo_dir"
python3 -m unittest discover -s tests -p 'test_*package*.py'
python3 -m unittest discover -s scripts -p 'test_probe_connectivity.py'
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release --message-format=json-render-diagnostics > "$work/build.jsonl"
artifact="$(python3 - "$work/build.jsonl" <<'PY'
import json, sys
items=[]
for line in open(sys.argv[1]):
    item=json.loads(line)
    target=item.get('target', {})
    if item.get('reason') == 'compiler-artifact' and target.get('name') == 'forti-client' and 'bin' in target.get('kind', []) and item.get('executable'):
        items.append(item['executable'])
if len(items) != 1:
    raise SystemExit('Expected one forti-client executable')
print(items[0])
PY
)"
lipo -verify_arch arm64 "$artifact"
"$artifact" --help >/dev/null
install -m 755 "$artifact" "$work/scripts/payload/forti-client"
install -m 755 scripts/macos-pkg/local-service.sh "$work/scripts/payload/local-service.sh"
install -m 755 scripts/macos-pkg/configure-service.py "$work/scripts/payload/configure-service.py"
install -m 644 scripts/macos-pkg/com.forti-client.daemon.plist "$work/scripts/payload/com.forti-client.daemon.plist"
install -m 644 scripts/macos-pkg/com.forti-client.agent.plist "$work/scripts/payload/com.forti-client.agent.plist"
macos_version="$(sw_vers -productVersion)"
macos_major="${macos_version%%.*}"
printf '%s\n' "$macos_major" > "$work/scripts/payload/macos-major"
package_version="$(date -u +%Y%m%d.%H%M%S)"
binary_version="$($artifact --version 2>/dev/null | awk '{print $2}')" || binary_version=0.1.0
package_name="forti-client-$binary_version-$package_version-macos$macos_major-arm64.pkg"
printf 'Package version: %s\nBinary version: %s\nmacOS major: %s\n' "$package_version" "$binary_version" "$macos_major" > "$work/scripts/payload/package-info.txt"
(cd "$work/scripts/payload" && shasum -a 256 forti-client local-service.sh configure-service.py com.forti-client.daemon.plist com.forti-client.agent.plist macos-major package-info.txt > SHA256SUMS)
install -m 755 scripts/macos-pkg/postinstall "$work/scripts/postinstall"
install -m 644 scripts/macos-pkg/install-user.sh "$work/scripts/install-user.sh"
pkgbuild --nopayload --scripts "$work/scripts" --identifier org.forti-client.agent --version "$package_version" "$work/component.pkg"
cat > "$work/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>FortiClient</title>
  <options customize="never" hostArchitectures="arm64"/>
  <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
  <volume-check><allowed-os-versions><os-version min="$macos_major" before="$((macos_major + 1))"/></allowed-os-versions></volume-check>
  <welcome file="welcome.txt" mime-type="text/plain"/>
  <conclusion file="conclusion.txt" mime-type="text/plain"/>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" visible="false"><pkg-ref id="org.forti-client.agent"/></choice>
  <pkg-ref id="org.forti-client.agent" version="$package_version" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
XML
mkdir "$work/resources"
cat > "$work/resources/welcome.txt" <<'TEXT'
FortiClient — macOS Apple Silicon

此安装包只安装 FortiClient 程序、launchd 模板和本地管理脚本。
它不包含 VPN 网关、可信 Wi-Fi、探测目标、凭据或其他环境配置。
安装不会自动连接 VPN；请在目标机完成受保护配置后再配置并启用服务。
TEXT
cat > "$work/resources/conclusion.txt" <<'TEXT'
安装完成后，先使用 configure-service.py 写入目标机配置，再使用 local-service.sh enable。
安装包不代表 VPN 已连接，也不包含任何网络环境配置。
TEXT
productbuild --distribution "$work/distribution.xml" --package-path "$work" --resources "$work/resources" "$work/$package_name"
pkgutil --expand-full "$work/$package_name" "$work/expanded"
(cd "$work/expanded/component.pkg/Scripts/payload" && shasum -a 256 -c SHA256SUMS)
install -m 600 "$work/$package_name" "$repo_dir/dist/$package_name"
(cd "$repo_dir/dist" && shasum -a 256 "$package_name" > "$package_name.sha256")
python3 scripts/prune-macos-packages.py "$repo_dir/dist"
printf 'Installer: %s/dist/%s\nThis private package is unsigned and contains no environment configuration.\n' "$repo_dir" "$package_name"
