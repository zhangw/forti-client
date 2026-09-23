import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
import unittest.mock

spec = importlib.util.spec_from_file_location(
    "probe", Path(__file__).with_name("probe-connectivity.py")
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def healthy():
    return dict(state="Running", desired="connected", daemon_pid=1, worker_pid=2,
                agent_present=True, control={"state": "accepting"}, resources={
                    role: dict(pid=pid, sampled_at=time.time(), fd_count=10,
                               limits={"soft": 256, "hard": None}, fd_error=None,
                               limits_error=None)
                    for role, pid in [("daemon", 1), ("worker", 2), ("agent", 3)]})


class Connection:
    def close(self):
        pass


class ProbeTests(unittest.TestCase):
    def test_unknown_stale_and_high_fd_are_not_healthy(self):
        status = healthy()
        self.assertEqual(probe.service_issues(status), [])
        status["resources"]["worker"]["fd_count"] = None
        self.assertIn("worker FD measurement unknown", probe.service_issues(status))
        status["resources"]["worker"]["fd_count"] = 205
        self.assertIn("worker FD usage >= 80%", probe.service_issues(status))
        status["resources"]["worker"]["sampled_at"] = time.time() - 181
        self.assertIn("worker resource snapshot stale", probe.service_issues(status))

    def test_old_service_is_reported_as_unknown(self):
        status = healthy()
        del status["resources"]
        self.assertIn("daemon resource snapshot unavailable", probe.service_issues(status))

    def test_every_unique_ipv4_address_is_probed_and_utun_is_prefix_matched(self):
        connected = []
        result = probe.probe_target(
            {"host": "office.example", "port": 443, "expected_interface": "utun"},
            resolver=lambda _host, _port: ["192.0.2.1", "192.0.2.2"],
            route_lookup=lambda address: {"192.0.2.1": "utun6", "192.0.2.2": "utun7"}[address],
            connector=lambda endpoint, timeout: connected.append((endpoint, timeout)) or Connection(),
        )
        self.assertTrue(result["ok"])
        self.assertEqual([item["address"] for item in result["addresses"]],
                         ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(connected, [(('192.0.2.1', 443), 5), (('192.0.2.2', 443), 5)])

    def test_resolver_deduplicates_ipv4_addresses(self):
        original = probe.socket.getaddrinfo
        probe.socket.getaddrinfo = lambda *_args, **_kwargs: [
            (2, 1, 6, "", ("192.0.2.1", 443)),
            (2, 1, 6, "", ("192.0.2.1", 443)),
            (2, 1, 6, "", ("192.0.2.2", 443)),
        ]
        try:
            self.assertEqual(probe.resolve_ipv4("office.example", 443),
                             ["192.0.2.1", "192.0.2.2"])
        finally:
            probe.socket.getaddrinfo = original

    def test_one_wrong_route_makes_target_unhealthy(self):
        result = probe.probe_target(
            {"host": "office.example", "port": 443, "expected_interface": "utun"},
            resolver=lambda _host, _port: ["192.0.2.1", "192.0.2.2"],
            route_lookup=lambda address: "en0" if address.endswith("2") else "utun6",
            connector=lambda _endpoint, timeout: Connection(),
        )
        self.assertTrue(result["dns_ok"])
        self.assertFalse(result["route_ok"])
        self.assertTrue(result["tcp_ok"])
        self.assertFalse(result["ok"])
        self.assertIn("192.0.2.2: expected interface=utun, actual=en0", result["issues"])

    def test_gateway_uses_exact_en0_and_explicit_10443(self):
        calls = []
        result = probe.probe_target(
            {"host": "vpn.example", "port": 10443, "expected_interface": "en0"},
            resolver=lambda _host, port: calls.append(("resolve", port)) or ["198.51.100.1"],
            route_lookup=lambda _address: "en0",
            connector=lambda endpoint, timeout: calls.append(("connect", endpoint)) or Connection(),
        )
        self.assertTrue(result["ok"])
        self.assertIn(("resolve", 10443), calls)
        self.assertIn(("connect", ("198.51.100.1", 10443)), calls)

    def test_one_tcp_failure_is_reported_without_skipping_other_addresses(self):
        calls = []

        def connect(endpoint, timeout):
            calls.append(endpoint)
            if endpoint[0] == "192.0.2.1":
                raise TimeoutError("timed out")
            return Connection()

        result = probe.probe_target(
            {"host": "office.example", "port": 443, "expected_interface": "utun"},
            resolver=lambda _host, _port: ["192.0.2.1", "192.0.2.2"],
            route_lookup=lambda _address: "utun6",
            connector=connect,
        )
        self.assertTrue(result["route_ok"])
        self.assertFalse(result["tcp_ok"])
        self.assertEqual(calls, [("192.0.2.1", 443), ("192.0.2.2", 443)])
        self.assertIn("192.0.2.1: TCP: TimeoutError: timed out", result["issues"])

    def test_network_and_service_health_are_reported_separately(self):
        target_result = {
            "host": "office.example", "port": 443, "expected_interface": "utun",
            "addresses": [{"address": "192.0.2.1", "interface": "utun6",
                           "route_ok": True, "tcp_ok": True, "tcp_ms": 1.0}],
            "issues": [], "dns_ok": True, "route_ok": True, "tcp_ok": True, "ok": True,
        }
        status = healthy()
        status["state"] = "WaitingToRetry"
        result = probe.collect_result(
            [{"host": "office.example", "port": 443, "expected_interface": "utun"}],
            "/unused",
            target_probe=lambda _target: target_result,
            status_probe=lambda _binary: status,
        )
        self.assertTrue(result["dns_ok"])
        self.assertTrue(result["route_ok"])
        self.assertTrue(result["tcp_ok"])
        self.assertTrue(result["connectivity_ok"])
        self.assertFalse(result["service_ok"])
        self.assertFalse(result["ok"])

    def test_legacy_host_cli_and_repeatable_targets_are_supported(self):
        args = probe.parse_args([
            "legacy.example", "--port", "8443", "--expected-interface", "any",
            "--target", "office.example:443=utun",
            "--target", "vpn.example:10443=en0", "--count", "1",
        ])
        self.assertEqual(args.targets, [
            {"host": "legacy.example", "port": 8443, "expected_interface": "any"},
            {"host": "office.example", "port": 443, "expected_interface": "utun"},
            {"host": "vpn.example", "port": 10443, "expected_interface": "en0"},
        ])

    def test_targets_file_is_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.json"
            path.write_text(json.dumps({"targets": [
                {"host": "office.example", "port": 443, "expected_interface": "utun"},
                {"host": "vpn.example", "port": 10443, "expected_interface": "en0"},
            ]}))
            args = probe.parse_args(["--targets-file", str(path), "--count", "1"])
        self.assertEqual(len(args.targets), 2)
        self.assertEqual(args.targets[1]["port"], 10443)

    def test_signature_ignores_address_order_and_latency(self):
        addresses = [
            {"address": "192.0.2.2", "interface": "utun7",
             "route_ok": True, "tcp_ok": True, "tcp_ms": 1},
            {"address": "192.0.2.1", "interface": "utun6",
             "route_ok": True, "tcp_ok": True, "tcp_ms": 2},
        ]
        target = {
            "host": "office.example", "port": 443, "expected_interface": "utun",
            "dns_ok": True, "route_ok": True, "tcp_ok": True,
            "addresses": addresses,
        }
        result = dict(ok=True, issues=[], targets=[target], service=healthy())
        initial = probe.report_signature(result)

        target["addresses"] = list(reversed(addresses))
        target["addresses"][0]["tcp_ms"] = 99
        result["service"]["resources"]["worker"]["fd_count"] = 20

        self.assertEqual(initial, probe.report_signature(result))
        self.assertEqual(
            [item["address"] for item in target["addresses"]],
            ["192.0.2.1", "192.0.2.2"],
            "signature normalization must not reorder JSON output",
        )

    def test_signature_reports_endpoint_state_change_after_reordering(self):
        addresses = [
            {"address": "192.0.2.1", "interface": "utun6",
             "route_ok": True, "tcp_ok": True},
            {"address": "192.0.2.2", "interface": "utun6",
             "route_ok": True, "tcp_ok": True},
        ]
        target = {
            "host": "office.example", "port": 443, "expected_interface": "utun",
            "dns_ok": True, "route_ok": True, "tcp_ok": True,
            "addresses": addresses,
        }
        result = dict(ok=True, issues=[], targets=[target], service=healthy())
        initial = probe.report_signature(result)

        target["addresses"] = list(reversed(addresses))
        target["addresses"][0]["interface"] = "en0"
        target["addresses"][0]["route_ok"] = False

        self.assertNotEqual(initial, probe.report_signature(result))

    def test_signature_reports_address_set_and_worker_changes(self):
        target = {
            "host": "office.example", "port": 443, "expected_interface": "utun",
            "dns_ok": True, "route_ok": True, "tcp_ok": True,
            "addresses": [{"address": "192.0.2.1", "interface": "utun6",
                           "route_ok": True, "tcp_ok": True}],
        }
        result = dict(ok=True, issues=[], targets=[target], service=healthy())
        initial = probe.report_signature(result)

        target["addresses"].append(
            {"address": "192.0.2.2", "interface": "utun6",
             "route_ok": True, "tcp_ok": True}
        )
        with_added_address = probe.report_signature(result)
        self.assertNotEqual(initial, with_added_address)

        target["addresses"].pop(0)
        self.assertNotEqual(with_added_address, probe.report_signature(result))
        after_removal = probe.report_signature(result)
        result["service"]["worker_pid"] = 4
        self.assertNotEqual(after_removal, probe.report_signature(result))
    def test_limited_run_returns_zero_when_all_checks_are_healthy(self):
        healthy_result = {"ok": True, "issues": [], "targets": [], "service": healthy()}
        with unittest.mock.patch.object(probe, "parse_args", return_value=type(
            "Args", (), {"count": 1, "targets": [], "binary": "/unused", "interval": 1}
        )()), unittest.mock.patch.object(
            probe, "collect_result", return_value=healthy_result
        ):
            self.assertEqual(probe.main([]), 0)

    def test_limited_run_returns_one_if_any_check_failed(self):
        failed = {"ok": False, "issues": ["route failed"], "targets": [], "service": healthy()}
        with unittest.mock.patch.object(probe, "parse_args", return_value=type(
            "Args", (), {"count": 1, "targets": [], "binary": "/unused", "interval": 1}
        )()), unittest.mock.patch.object(probe, "collect_result", return_value=failed):
            self.assertEqual(probe.main([]), 1)

    def test_multiple_limited_checks_remember_an_intermediate_failure(self):
        healthy_result = {"ok": True, "issues": [], "targets": [], "service": healthy()}
        failed = {"ok": False, "issues": ["route failed"], "targets": [], "service": healthy()}
        with unittest.mock.patch.object(probe, "parse_args", return_value=type(
            "Args", (), {"count": 2, "targets": [], "binary": "/unused", "interval": 1}
        )()), unittest.mock.patch.object(
            probe, "collect_result", side_effect=[failed, healthy_result]
        ), unittest.mock.patch.object(probe.time, "sleep"):
            self.assertEqual(probe.main([]), 1)



if __name__ == "__main__":
    unittest.main()
