#!/usr/bin/env python3
"""Write the root-owned FortiClient service config supplied by the target admin."""
import argparse
import json
import os
import pathlib
import re
import stat
import tempfile

BASE = pathlib.Path('/Library/Application Support/FortiClient')
CONFIG = BASE / 'config.json'
HOST = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z')
parser = argparse.ArgumentParser(description='Configure FortiClient without storing credentials.')
parser.add_argument('--server', required=True)
parser.add_argument('--port', type=int, default=443)
parser.add_argument('--trusted-wifi', action='append', default=[])
args = parser.parse_args()
if os.geteuid() != 0:
    raise SystemExit('run as administrator')
if not HOST.fullmatch(args.server) or not 1 <= args.port <= 65535:
    raise SystemExit('server must be a DNS hostname and port must be 1..65535')
uid = os.stat('/dev/console').st_uid
if uid == 0:
    raise SystemExit('log in to the target desktop before configuring the service')
if BASE.is_symlink() or (BASE.exists() and not BASE.is_dir()):
    raise SystemExit('FortiClient installation directory is unsafe')
if CONFIG.is_symlink() or (CONFIG.exists() and not CONFIG.is_file()):
    raise SystemExit('FortiClient config path is unsafe')
if BASE.exists():
    mode = BASE.stat().st_mode
    if BASE.stat().st_uid != 0 or mode & 0o022:
        raise SystemExit('FortiClient installation directory must be root-owned and private to groups')
config = {'uid': uid, 'server': args.server, 'port': args.port, 'trusted_wifi': args.trusted_wifi}
BASE.mkdir(mode=0o755, parents=True, exist_ok=True)
os.chown(BASE, 0, 0)
fd, name = tempfile.mkstemp(prefix='.config.', dir=BASE)
os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
with os.fdopen(fd, 'w') as stream:
    json.dump(config, stream, indent=2)
    stream.write('\n')
os.chown(name, 0, 0)
os.replace(name, CONFIG)
os.chown(CONFIG, 0, 0)
print(f'Wrote {CONFIG}; service remains stopped.')
