import importlib.util
from pathlib import Path
import time
import unittest

spec = importlib.util.spec_from_file_location("probe", Path(__file__).with_name("probe-connectivity.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def healthy():
    return dict(state="Running", desired="connected", daemon_pid=1, worker_pid=2,
                agent_present=True, control={"state": "accepting"}, resources={
                    role: dict(pid=pid, sampled_at=time.time(), fd_count=10,
                               limits={"soft": 256, "hard": None}, fd_error=None, limits_error=None)
                    for role, pid in [("daemon", 1), ("worker", 2), ("agent", 3)]})


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

    def test_signature_suppresses_noise_but_reports_restart_and_recovery(self):
        result = dict(ok=True, interface="utun6", issues=[], service=healthy(), tcp_ms=1)
        initial = probe.report_signature(result)
        result["tcp_ms"] = 99
        result["service"]["resources"]["worker"]["fd_count"] = 20
        self.assertEqual(initial, probe.report_signature(result))
        result["service"]["worker_pid"] = 4
        self.assertNotEqual(initial, probe.report_signature(result))
        result["ok"] = False
        result["issues"] = ["connectivity failed"]
        failed = probe.report_signature(result)
        self.assertEqual(failed, probe.report_signature(result))
        result["ok"], result["issues"] = True, []
        self.assertNotEqual(failed, probe.report_signature(result))


if __name__ == "__main__":
    unittest.main()
