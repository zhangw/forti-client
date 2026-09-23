#!/bin/bash
# User-facing service controls for the installed managed FortiClient.
set -euo pipefail
base='/Library/Application Support/FortiClient'
binary="$base/forti-client"
daemon='/Library/LaunchDaemons/com.forti-client.daemon.plist'
agent='/Library/LaunchAgents/com.forti-client.agent.plist'
config="$base/config.json"
read_uid() {
  if [[ -f "$config" && ! -L "$config" ]]; then
    /usr/bin/plutil -extract uid raw -o - "$config" 2>/dev/null && return
  fi
  /usr/bin/stat -f '%u' /dev/console
}
case "${1:-}" in
  enable)
    [[ -f "$config" && ! -L "$config" ]] || { echo 'Configure FortiClient before enabling services.' >&2; exit 1; }
    uid=$(read_uid)
    "$binary" check-service-config "$config"
    /bin/launchctl bootstrap system "$daemon" 2>/dev/null || /bin/launchctl kickstart -k system/com.forti-client.daemon
    /bin/launchctl bootstrap "gui/$uid" "$agent" 2>/dev/null || /bin/launchctl kickstart -k "gui/$uid/com.forti-client.agent"
    echo 'FortiClient services enabled; VPN connection intent remains controlled by the service.'
    ;;
  disable)
    uid=$(read_uid)
    /bin/launchctl bootout "gui/$uid/com.forti-client.agent" 2>/dev/null || true
    /bin/launchctl bootout system/com.forti-client.daemon 2>/dev/null || true
    echo 'FortiClient services disabled.'
    ;;
  status)
    "$binary" ctl status
    ;;
  *) echo "Usage: $0 enable|disable|status" >&2; exit 2;;
esac
