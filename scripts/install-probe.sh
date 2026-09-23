#!/bin/bash
# Install only the read-only connectivity probe and its targets; do not restart VPN services.
set -euo pipefail

if [[ $EUID != 0 ]]; then
    echo 'Administrator authentication is required.' >&2
    exit 1
fi

stage=$(cd "$(dirname "$0")" && pwd)
base='/Library/Application Support/FortiClient'
probe_source="$stage/probe-connectivity.py"
module_source="$stage/probe_targets.py"
targets_source="$stage/probe-targets.json"
probe_target="$base/probe-connectivity.py"
module_target="$base/probe_targets.py"
targets_target="$base/probe-targets.json"
probe_new="$base/.probe-connectivity.py.new.$$"
module_new="$base/.probe_targets.py.new.$$"
targets_new="$base/.probe-targets.json.new.$$"

cleanup() {
    /bin/rm -f "$probe_new" "$module_new" "$targets_new"
}
trap cleanup EXIT

for source in "$probe_source" "$module_source" "$targets_source"; do
    if [[ -L "$source" || ! -f "$source" ]]; then
        echo "Staged input must be a regular non-symlink file: $source" >&2
        exit 1
    fi
done
if [[ -L "$base" || ! -d "$base" ]]; then
    echo "FortiClient installation directory is missing or unsafe: $base" >&2
    exit 1
fi
owner=$(/usr/bin/stat -f '%Su:%Sg' "$base")
mode=$(/usr/bin/stat -f '%Lp' "$base")
if [[ "$owner" != root:wheel ]] || (( (8#$mode & 0022) != 0 )); then
    echo "FortiClient installation directory must be root:wheel and not group/world writable: $base" >&2
    exit 1
fi
for target in "$probe_target" "$module_target" "$targets_target"; do
    if [[ -L "$target" || ( -e "$target" && ! -f "$target" ) ]]; then
        echo "Refusing unsafe installation target: $target" >&2
        exit 1
    fi
done

# Validate the staged target file with the same module used at runtime and staging.
/usr/bin/python3 - "$stage" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from probe_targets import load_targets_file
load_targets_file(sys.argv[1] + "/probe-targets.json")
PY

# Prepare both files before replacing either live path.
/usr/bin/install -m 755 -o root -g wheel "$probe_source" "$probe_new"
/usr/bin/install -m 755 -o root -g wheel "$module_source" "$module_new"
/usr/bin/install -m 644 -o root -g wheel "$targets_source" "$targets_new"
/bin/mv -f "$probe_new" "$probe_target"
/bin/mv -f "$module_new" "$module_target"
/bin/mv -f "$targets_new" "$targets_target"
trap - EXIT

printf 'Installed read-only connectivity probe without restarting FortiClient.\n'
printf 'Run: /usr/bin/python3 "%s" --targets-file "%s" --count 1\n' "$probe_target" "$targets_target"
