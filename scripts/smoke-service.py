#!/usr/bin/env python3
"""Privileged, disruptive smoke test. Leaves the managed VPN connected."""
import ipaddress
import json
import os
import pathlib
import re
import signal
import subprocess
import time

BASE = pathlib.Path('/Library/Application Support/FortiClient')
BINARY = str(BASE / 'forti-client')
REPORT = pathlib.Path('/Library/Logs/FortiClient/smoke-report.json')
KEY = 'State:/Network/Service/forti-client/DNS'
results = []

def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=35, **kwargs)

def ctl(command):
    result = run([BINARY, 'ctl', command])
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout) if command == 'status' else result.stdout

def record(name, **fields):
    results.append(dict(check=name, passed=True, **fields))
    print(json.dumps(results[-1]), flush=True)
    REPORT.write_text(json.dumps(results, indent=2) + '\n')
    os.chmod(REPORT, 0o644)

def wait_for(predicate, timeout=150):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = ctl('status')
            if predicate(last):
                return last
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            last = str(exc)
        time.sleep(1)
    raise RuntimeError(f'timed out waiting for service: {last}')

def dns_key():
    return run(['/usr/sbin/scutil'], input=f'show {KEY}\n').stdout

def check_network():
    config = json.loads((BASE / 'config.json').read_text())
    addresses = re.findall(r'\d+\s*:\s*(\d+\.\d+\.\d+\.\d+)', dns_key())
    internal = next((ip for ip in addresses if ipaddress.ip_address(ip).is_private), None)
    if not internal:
        raise RuntimeError('No private VPN DNS server; cannot verify internal path')
    route = run(['/sbin/route', '-n', 'get', internal])
    match = re.search(r'interface:\s*(utun\d+)', route.stdout)
    if not match:
        raise RuntimeError('VPN DNS is not routed through a utun interface')
    interface = match[1]
    query = run(['/usr/bin/dig', '@' + internal, config['server'], 'A', '+short', '+time=3', '+tries=1'])
    if query.returncode or not any(re.fullmatch(r'\d+\.\d+\.\d+\.\d+', line) for line in query.stdout.splitlines()):
        raise RuntimeError('Internal DNS query through VPN failed')
    routes = run(['/usr/sbin/netstat', '-rn', '-f', 'inet']).stdout
    count = len(re.findall(r'\b' + interface + r'\b', routes))
    if not count:
        raise RuntimeError('No VPN routes installed')
    return dict(interface=interface, route_count=count, internal_dns_query=True)

def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False

if os.geteuid() != 0:
    raise SystemExit('Run as administrator: this test deliberately kills managed processes.')

try:
    initial = wait_for(lambda s: s['state'] == 'Running' and s['agent_present'], timeout=330)
    record('launchd_start_and_connection', **check_network())
    interface = results[-1]['interface']
    if run(['/bin/launchctl', 'print', 'system/com.forti-client.daemon']).returncode:
        raise RuntimeError('Daemon is not managed by launchd')
    ctl('pause')
    paused = wait_for(lambda s: s['state'] == 'Paused' and s['worker_pid'] is None)
    if 'No such key' not in dns_key():
        raise RuntimeError('Pause left VPN DNS installed')
    routes = run(['/usr/sbin/netstat', '-rn', '-f', 'inet']).stdout
    if re.search(r'\b' + interface + r'\b', routes):
        raise RuntimeError('Pause left routes on the old VPN interface')
    record('pause_cleans_dns_and_routes')

    old_daemon = paused['daemon_pid']
    os.kill(old_daemon, signal.SIGKILL)
    recovered = wait_for(lambda s: s['daemon_pid'] != old_daemon and s['state'] == 'Paused' and s['agent_present'])
    if recovered['desired'] != 'paused' or recovered['worker_pid'] is not None:
        raise RuntimeError('Daemon restart forgot the pause')
    record('launchd_restart_preserves_pause')

    ctl('resume')
    running = wait_for(lambda s: s['state'] == 'Running' and s['worker_pid'] is not None, timeout=330)
    record('resume_connects', **check_network())

    old_worker = running['worker_pid']
    os.kill(old_worker, signal.SIGKILL)
    wait_for(lambda s: s['worker_pid'] is None and s['state'] == 'WaitingToRetry', timeout=20)
    if 'No such key' not in dns_key():
        raise RuntimeError('Worker crash left stale DNS during backoff')
    record('worker_crash_cleans_dns_before_retry')
    running = wait_for(lambda s: s['state'] == 'Running' and s['worker_pid'] not in (None, old_worker), timeout=330)
    record('worker_crash_recovers', **check_network())

    old_daemon, old_worker = running['daemon_pid'], running['worker_pid']
    os.kill(old_daemon, signal.SIGKILL)
    final = wait_for(lambda s: s['daemon_pid'] != old_daemon and s['state'] == 'Running' and s['worker_pid'] not in (None, old_worker) and s['agent_present'], timeout=330)
    if alive(old_worker):
        raise RuntimeError('launchd left the previous VPN worker alive')
    record('daemon_crash_recovers_without_orphan', **check_network())
    record('final_connected', daemon_pid=final['daemon_pid'], worker_pid=final['worker_pid'])
except Exception as exc:
    results.append(dict(check='failure', passed=False, error=str(exc)))
    REPORT.write_text(json.dumps(results, indent=2) + '\n')
    os.chmod(REPORT, 0o644)
    # Restore connection intent after a failed test; never leave a test pause.
    try:
        ctl('resume')
    except Exception:
        pass
    raise
