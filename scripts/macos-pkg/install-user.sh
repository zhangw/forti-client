#!/bin/bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Administrator authentication required.' >&2; exit 1; }
stage=$(cd "$(dirname "$0")" && pwd)
base='/Library/Application Support/FortiClient'
daemon='/Library/LaunchDaemons/com.forti-client.daemon.plist'
agent='/Library/LaunchAgents/com.forti-client.agent.plist'
paths=(
  "$base/forti-client" "$base/local-service.sh" "$base/configure-service.py"
  "$base/package-info.txt" "$base/config.json" "$base/intent.json"
  "$daemon" "$agent"
)
for path in "$base" /Library/Logs/FortiClient /Library/LaunchDaemons /Library/LaunchAgents; do
  [[ ! -L "$path" ]] || { echo "Refusing symlink: $path" >&2; exit 1; }
done
if [[ -e "$base" ]]; then
  echo "Existing FortiClient installation directory; refusing fresh install: $base" >&2
  exit 1
fi
if /bin/launchctl print system/com.forti-client.daemon >/dev/null 2>&1; then
  echo 'FortiClient daemon is already loaded; refusing installation.' >&2
  exit 1
fi
uid=$(/usr/bin/stat -f '%u' /dev/console)
if [[ "$uid" != 0 ]] && /bin/launchctl print "gui/$uid/com.forti-client.agent" >/dev/null 2>&1; then
  echo 'FortiClient agent is already loaded; refusing installation.' >&2
  exit 1
fi
for path in "${paths[@]}"; do
  if [[ -L "$path" ]]; then
    echo "Refusing symlink: $path" >&2
    exit 1
  fi
  if [[ -e "$path" ]]; then
    echo "Existing FortiClient installation path; refusing fresh install: $path" >&2
    exit 1
  fi
done
/usr/bin/install -d -o root -g wheel -m 755 "$base" /Library/Logs/FortiClient
installed=()
rollback() {
  status=$?
  trap - EXIT
  if [[ $status -ne 0 ]]; then
    for path in "${installed[@]}"; do /bin/rm -f "$path"; done
    echo 'Installation failed; newly installed files were removed.' >&2
  fi
  exit "$status"
}
trap rollback EXIT
copy_file() {
  local source=$1 target=$2 mode=$3
  /usr/bin/install -m "$mode" -o root -g wheel "$source" "$target"
  installed+=("$target")
}
copy_file "$stage/forti-client" "$base/forti-client" 755
copy_file "$stage/local-service.sh" "$base/local-service.sh" 755
copy_file "$stage/configure-service.py" "$base/configure-service.py" 755
copy_file "$stage/com.forti-client.daemon.plist" "$daemon" 644
copy_file "$stage/com.forti-client.agent.plist" "$agent" 644
copy_file "$stage/package-info.txt" "$base/package-info.txt" 644
(umask 077; printf '%s\n' '{"connected":false}' > "$base/intent.json")
/usr/bin/chown root:wheel "$base/intent.json"
/bin/chmod 600 "$base/intent.json"
installed+=("$base/intent.json")
"$base/forti-client" --help >/dev/null
trap - EXIT
echo 'FortiClient installed without enabling or starting VPN services.'
