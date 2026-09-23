import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "scripts" / "build-macos-pkg.sh"
PACKAGE_DIR = ROOT / "scripts" / "macos-pkg"


class MacOSPackageTests(unittest.TestCase):
    def test_build_script_and_payload_sources_exist(self):
        self.assertTrue(PACKAGE.is_file())
        self.assertTrue(PACKAGE.stat().st_mode & 0o111)
        for name in (
            "postinstall",
            "install-user.sh",
            "configure-service.py",
            "local-service.sh",
            "com.forti-client.daemon.plist",
            "com.forti-client.agent.plist",
        ):
            self.assertTrue((PACKAGE_DIR / name).is_file(), name)

    def test_shell_and_python_sources_are_valid(self):
        for name in ("build-macos-pkg.sh",):
            subprocess.run(["bash", "-n", str(ROOT / "scripts" / name)], check=True)
        for path in (
            ROOT / "scripts" / "prune-macos-packages.py",
            PACKAGE_DIR / "configure-service.py",
        ):
            subprocess.run(["python3", "-m", "py_compile", str(path)], check=True)

    def test_package_does_not_reference_local_environment_inputs(self):
        paths = [PACKAGE, *PACKAGE_DIR.iterdir()]
        text = "\n".join(path.read_text() for path in paths if path.is_file())
        forbidden = (
            "local-" + "run.sh",
            "probe-" + "targets.json",
            "webull" + "broker",
            "Webull" + "-pro",
            "/Users/" + "vincent",
            "192.168." + "40",
            "10.8." + "2",
        )
        for value in forbidden:
            self.assertNotIn(value, text)

    def test_installer_does_not_start_services(self):
        text = "\n".join(
            (PACKAGE_DIR / name).read_text()
            for name in ("postinstall", "install-user.sh")
        )
        self.assertNotRegex(text, r"launchctl\s+(bootstrap|kickstart)")
        self.assertNotIn("ctl resume", text)

    def test_retention_pattern_matches_only_forti_arm64_packages(self):
        pattern = re.compile(r"^forti-client-.+-(\d{8}\.\d{6})-macos\d+-arm64\.pkg$")
        self.assertIsNotNone(pattern.match("forti-client-0.1.0-20260923.093541-macos27-arm64.pkg"))
        self.assertIsNone(pattern.match("forti-client-0.1.0-20260923.093541-macos27-x86_64.pkg"))


if __name__ == "__main__":
    unittest.main()
