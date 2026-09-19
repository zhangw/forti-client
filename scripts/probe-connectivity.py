#!/usr/bin/env python3
"""Probe route selection, TCP connectivity, and the managed service."""
import argparse
import json
import socket
import subprocess
import time
from datetime import datetime, timezone

DEFAULT_BINARY = "/Library/Application Support/FortiClient/forti-client"


def route_for(address):
    result = subprocess.run(
        ["/sbin/route", "-n", "get", address],
        capture_output=True,
        text=True,
        timeout=5,
    )
    interface = None
    for line in result.stdout.splitlines():
        if line.strip().startswith("interface:"):
            interface = line.split(":", 1)[1].strip()
            break
    if result.returncode != 0 or interface is None:
        raise RuntimeError(result.stderr.strip() or "route lookup failed")
    return interface


def probe(host, port):
    started = time.monotonic()
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    address = addresses[0][4][0]
    interface = route_for(address)
    with socket.create_connection((address, port), timeout=5):
        pass
    return {
        "time": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "address": address,
        "port": port,
        "interface": interface,
        "tcp_ms": round((time.monotonic() - started) * 1000, 1),
        "ok": True,
    }


def service_status(binary):
    result = subprocess.run(
        [binary, "ctl", "status", "--json"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"ctl status exited {result.returncode}")
    return json.loads(result.stdout)


def service_issues(status):
    issues = []
    if status.get("state") != "Running":
        issues.append(f"state={status.get('state')!r}")
    if status.get("desired") != "connected":
        issues.append(f"desired={status.get('desired')!r}")
    if not status.get("daemon_pid"):
        issues.append("daemon_pid missing")
    if status.get("state") == "Running" and not status.get("worker_pid"):
        issues.append("worker_pid missing")
    if not status.get("agent_present"):
        issues.append("login agent unavailable")
    if status.get("control", {}).get("state") != "accepting":
        issues.append("control interface unhealthy or health unknown")
    resources = status.get("resources") or {}
    for role in ("daemon", "worker", "agent"):
        if role == "worker" and not status.get("worker_pid"):
            continue
        snapshot = resources.get(role)
        if not snapshot:
            issues.append(f"{role} resource snapshot unavailable")
            continue
        expected_pid = status.get(f"{role}_pid")
        if expected_pid and snapshot.get("pid") != expected_pid:
            issues.append(f"{role} resource PID mismatch")
        if time.time() - snapshot.get("sampled_at", 0) > 180:
            issues.append(f"{role} resource snapshot stale")
        count, limits = snapshot.get("fd_count"), snapshot.get("limits")
        if (count is None or limits is None or snapshot.get("fd_error")
                or snapshot.get("limits_error")):
            issues.append(f"{role} FD measurement unknown")
        elif limits.get("soft") is not None and count * 100 >= limits["soft"] * 80:
            issues.append(f"{role} FD usage >= 80%")
    return issues


def report_signature(result):
    service = result.get("service") or {}
    return (result["ok"], result.get("interface"), tuple(result["issues"]),
            service.get("state"), service.get("desired"),
            service.get("daemon_pid"), service.get("worker_pid"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--count", type=int, default=0, help="0 means run forever")
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="forti-client control binary")
    args = parser.parse_args()
    if not args.host or args.interval < 1 or args.count < 0 or not 1 <= args.port <= 65535:
        parser.error("nonempty host, positive interval, nonnegative count and valid port required")
    completed = 0
    previous_signature = None
    while args.count == 0 or completed < args.count:
        started = time.monotonic()
        try:
            result = probe(args.host, args.port)
        except Exception as error:
            result = {
                "time": datetime.now(timezone.utc).isoformat(),
                "host": args.host,
                "port": args.port,
                "ok": False,
                "error": f"{type(error).__name__}: {error}",
            }
        try:
            status = service_status(args.binary)
            result["service"] = status
            result["service_issues"] = service_issues(status)
        except Exception as error:
            result["service"] = None
            result["service_issues"] = [f"ctl status: {type(error).__name__}: {error}"]
        if result.get("interface") and not result["interface"].startswith("utun"):
            result.setdefault("issues", []).append(f"unexpected interface={result['interface']}")
        if not result.get("ok"):
            result.setdefault("issues", []).append(result.get("error", "connectivity failed"))
        result["issues"] = result.get("issues", []) + result.pop("service_issues")
        result["connectivity_ok"] = result["ok"]
        result["ok"] = not result["issues"]
        signature = report_signature(result)
        if signature != previous_signature:
            result["event"] = ("anomaly" if result["issues"] else
                               "recovered" if previous_signature and not previous_signature[0] else
                               "initial" if previous_signature is None else "changed")
            print(json.dumps(result, sort_keys=True), flush=True)
        previous_signature = signature
        completed += 1
        if args.count == 0 or completed < args.count:
            time.sleep(max(0, args.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
