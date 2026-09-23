#!/usr/bin/env python3
"""Probe every target address, route selection, TCP connectivity, and Forti service."""
import argparse
import json
import pathlib
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from probe_targets import load_targets_file, validate_target

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


def resolve_ipv4(host, port):
    addresses = []
    seen = set()
    for entry in socket.getaddrinfo(
        host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
    ):
        address = entry[4][0]
        if address not in seen:
            seen.add(address)
            addresses.append(address)
    if not addresses:
        raise RuntimeError("no IPv4 addresses returned")
    return addresses


def interface_matches(actual, expected):
    if expected == "any":
        return True
    if expected == "utun":
        return bool(actual) and actual.startswith("utun")
    return actual == expected


def parse_target(value):
    try:
        endpoint, expected = value.rsplit("=", 1)
        host, port_text = endpoint.rsplit(":", 1)
        port = int(port_text)
    except (ValueError, AttributeError) as error:
        raise ValueError(
            f"invalid target {value!r}; expected HOST:PORT=INTERFACE"
        ) from error
    return validate_target(
        {"host": host, "port": port, "expected_interface": expected}
    )


def probe_target(target, resolver=resolve_ipv4, route_lookup=route_for,
                 connector=socket.create_connection, clock=time.monotonic):
    target = validate_target(target)
    result = dict(target, addresses=[], issues=[])
    try:
        addresses = resolver(target["host"], target["port"])
    except Exception as error:
        result.update(
            dns_ok=False,
            route_ok=False,
            tcp_ok=False,
            ok=False,
            error=f"{type(error).__name__}: {error}",
        )
        result["issues"].append(f"DNS: {result['error']}")
        return result

    result["dns_ok"] = True
    for address in addresses:
        endpoint = {"address": address}
        try:
            interface = route_lookup(address)
            endpoint["interface"] = interface
            endpoint["route_ok"] = interface_matches(
                interface, target["expected_interface"]
            )
            if not endpoint["route_ok"]:
                result["issues"].append(
                    f"{address}: expected interface={target['expected_interface']}, "
                    f"actual={interface}"
                )
        except Exception as error:
            endpoint["route_ok"] = False
            endpoint["route_error"] = f"{type(error).__name__}: {error}"
            result["issues"].append(f"{address}: route: {endpoint['route_error']}")

        started = clock()
        connection = None
        try:
            connection = connector((address, target["port"]), timeout=5)
            endpoint["tcp_ok"] = True
            endpoint["tcp_ms"] = round((clock() - started) * 1000, 1)
        except Exception as error:
            endpoint["tcp_ok"] = False
            endpoint["tcp_error"] = f"{type(error).__name__}: {error}"
            result["issues"].append(f"{address}: TCP: {endpoint['tcp_error']}")
        finally:
            if connection is not None:
                connection.close()
        result["addresses"].append(endpoint)

    result["route_ok"] = all(item["route_ok"] for item in result["addresses"])
    result["tcp_ok"] = all(item["tcp_ok"] for item in result["addresses"])
    result["ok"] = result["dns_ok"] and result["route_ok"] and result["tcp_ok"]
    return result


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


def collect_result(targets, binary, target_probe=probe_target,
                   status_probe=service_status):
    target_results = [target_probe(target) for target in targets]
    result = {
        "time": datetime.now(timezone.utc).isoformat(),
        "targets": target_results,
        "dns_ok": all(item["dns_ok"] for item in target_results),
        "route_ok": all(item["route_ok"] for item in target_results),
        "tcp_ok": all(item["tcp_ok"] for item in target_results),
    }
    result["connectivity_ok"] = (
        result["dns_ok"] and result["route_ok"] and result["tcp_ok"]
    )
    issues = [
        f"{item['host']}:{item['port']}: {issue}"
        for item in target_results
        for issue in item["issues"]
    ]
    try:
        status = status_probe(binary)
        result["service"] = status
        service_problems = service_issues(status)
    except Exception as error:
        result["service"] = None
        service_problems = [f"ctl status: {type(error).__name__}: {error}"]
    result["service_ok"] = not service_problems
    result["issues"] = issues + service_problems
    result["ok"] = result["connectivity_ok"] and result["service_ok"]

    # Preserve the most-used fields from the former single-target output while
    # exposing every address under targets[0].addresses.
    if len(target_results) == 1:
        target = target_results[0]
        result["host"] = target["host"]
        result["port"] = target["port"]
        if target["addresses"]:
            first = target["addresses"][0]
            result["address"] = first["address"]
            result["interface"] = first.get("interface")
            result["tcp_ms"] = first.get("tcp_ms")
    return result


def report_signature(result):
    service = result.get("service") or {}
    targets = result.get("targets")
    if targets is None:
        # Compatibility for callers constructing the old result shape.
        network = (result.get("interface"),)
    else:
        network = tuple(
            (
                target.get("host"),
                target.get("port"),
                target.get("expected_interface"),
                target.get("dns_ok"),
                target.get("route_ok"),
                target.get("tcp_ok"),
                tuple(sorted(
                    (
                        item.get("address"),
                        item.get("interface"),
                        item.get("route_ok"),
                        item.get("tcp_ok"),
                        item.get("route_error"),
                        item.get("tcp_error"),
                    )
                    for item in target.get("addresses", [])
                )),
            )
            for target in targets
        )
    return (
        result["ok"],
        network,
        tuple(result["issues"]),
        service.get("state"),
        service.get("desired"),
        service.get("daemon_pid"),
        service.get("worker_pid"),
    )


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", help="legacy single target hostname")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument(
        "--expected-interface",
        default="utun",
        help="legacy target interface: utun, any, or an exact interface",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="HOST:PORT=INTERFACE",
        help="repeatable target; INTERFACE is utun, any, or an exact name",
    )
    parser.add_argument("--targets-file", help="JSON file containing a targets array")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--count", type=int, default=0, help="0 means run forever")
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="forti-client control binary")
    args = parser.parse_args(argv)
    if args.interval < 1 or args.count < 0:
        parser.error("positive interval and nonnegative count required")
    try:
        targets = []
        if args.host is not None:
            targets.append(validate_target({
                "host": args.host,
                "port": args.port,
                "expected_interface": args.expected_interface,
            }))
        targets.extend(parse_target(value) for value in args.target)
        if args.targets_file:
            targets.extend(load_targets_file(args.targets_file)["targets"])
        if not targets:
            raise ValueError("provide host, --target, or --targets-file")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    args.targets = targets
    return args


def main(argv=None):
    args = parse_args(argv)
    completed = 0
    previous_signature = None
    had_failure = False
    try:
        while args.count == 0 or completed < args.count:
            started = time.monotonic()
            result = collect_result(args.targets, args.binary)
            had_failure = had_failure or not result["ok"]
            signature = report_signature(result)
            if signature != previous_signature:
                result["event"] = (
                    "anomaly" if result["issues"] else
                    "recovered" if previous_signature and not previous_signature[0] else
                    "initial" if previous_signature is None else "changed"
                )
                print(json.dumps(result, sort_keys=True), flush=True)
            previous_signature = signature
            completed += 1
            if args.count == 0 or completed < args.count:
                time.sleep(max(0, args.interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        return 0
    return int(args.count > 0 and had_failure)


if __name__ == "__main__":
    sys.exit(main())
