#!/bin/bash
# Run the staged copy as administrator, passing the verified legacy VPN PID.
set -euo pipefail
if [[ $EUID != 0 ]]; then echo 'Administrator authentication is required.' >&2; exit 1; fi
stage=$(cd "$(dirname "$0")" && pwd)
base='/Library/Application Support/FortiClient'
daemon='/Library/LaunchDaemons/com.forti-client.daemon.plist'
agent='/Library/LaunchAgents/com.forti-client.agent.plist'
old_pid=${1:-}
if [[ -z "$old_pid" || "$old_pid" == *[!0-9]* ]]; then echo 'Pass the verified existing VPN PID.' >&2; exit 1; fi
uid=$(/usr/bin/plutil -extract uid raw -o - "$stage/config.json")
/bin/launchctl print "gui/$uid" >/dev/null
/usr/bin/plutil -lint "$stage/com.forti-client.daemon.plist" "$stage/com.forti-client.agent.plist"
if /bin/launchctl print system/com.forti-client.daemon >/dev/null 2>&1; then
    echo 'Service is already installed; use forti-client ctl pause and an explicit upgrade procedure.' >&2; exit 1
fi
# Fail before touching the live VPN if the staged executable/config is unusable.
"$stage/forti-client" --help >/dev/null
"$stage/forti-client" check-service-config "$stage/config.json"
for dir in "$base" /Library/Logs/FortiClient; do
    if [[ -L "$dir" ]]; then echo "Refusing symlink: $dir" >&2; exit 1; fi
    /usr/bin/install -d -o root -g wheel -m 755 "$dir"
done
/usr/bin/install -m 755 -o root -g wheel "$stage/forti-client" "$base/forti-client"
/usr/bin/install -m 600 -o root -g wheel "$stage/config.json" "$base/config.json"
if [[ ! -e "$base/intent.json" ]]; then
    (umask 077; echo '{"connected":true}' > "$base/intent.json")
fi
/usr/bin/install -m 644 -o root -g wheel "$stage/com.forti-client.daemon.plist" "$daemon"
/usr/bin/install -m 644 -o root -g wheel "$stage/com.forti-client.agent.plist" "$agent"
command=$(/bin/ps -p "$old_pid" -o comm=)
owner=$(/bin/ps -p "$old_pid" -o uid= | /usr/bin/tr -d ' ')
if [[ "$command" != './target/release/forti-client' || "$owner" != 0 ]]; then
    echo 'Legacy process identity changed; refusing to signal it.' >&2; exit 1
fi
/bin/kill -TERM "$old_pid"
for ((i=0; i<40; i++)); do
    if ! /bin/kill -0 "$old_pid" 2>/dev/null; then break; fi
    /bin/sleep 1
done
if /bin/kill -0 "$old_pid" 2>/dev/null; then
    echo 'Legacy VPN did not stop; new service not started.' >&2; exit 1
fi
/bin/launchctl bootstrap system "$daemon"
/bin/launchctl bootstrap "gui/$uid" "$agent"
/bin/launchctl print system/com.forti-client.daemon
printf '\nInstalled. Check: "%s/forti-client" ctl status\n' "$base"

if [[ ${2:-} == --smoke ]]; then
    /usr/bin/python3 "$stage/smoke-service.py"
fi
