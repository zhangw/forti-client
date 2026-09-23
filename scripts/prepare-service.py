#!/usr/bin/env python3
"""Stage a launchd installation from the existing local-run.sh; no privileged writes."""
import json
import os
import pathlib
import plistlib
import re
import shlex
import shutil
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "scripts"))
from probe_targets import load_targets_file


def copy_probe_module(source, destination):
    shutil.copy2(source, destination)
    os.chmod(destination, 0o755)

stage = root / "target/service-install"
stage.mkdir(parents=True, exist_ok=True)
os.chmod(stage, 0o700)
lines = [line for line in (root / "local-run.sh").read_text().splitlines() if line.startswith("exec ")]
if len(lines) != 1:
    raise SystemExit("Expected one exec command in local-run.sh")
args = shlex.split(lines[0])
if "--saml" not in args:
    raise SystemExit("Service mode currently requires SAML")
def option(name, default=None):
    return args[args.index(name) + 1] if name in args else default
config = dict(uid=os.getuid(), server=option("--server"), port=int(option("--port", "443")),
              trusted_wifi=[args[i + 1] for i, arg in enumerate(args) if arg == "--trusted-wifi"])
if not config["server"] or config["uid"] == 0:
    raise SystemExit("Run preparation as the intended non-root user")
(stage / "config.json").write_text(json.dumps(config, indent=2) + "\n")
os.chmod(stage / "config.json", 0o600)

probe_targets_path = root / "probe-targets.json"
try:
    probe_targets = (
        None if probe_targets_path.is_symlink()
        else None if not probe_targets_path.exists()
        else load_targets_file(probe_targets_path)
    )
    if probe_targets_path.is_symlink():
        raise ValueError("probe-targets.json must not be a symlink")
except ValueError as error:
    raise SystemExit(str(error)) from error

shutil.copy2(root / "target/release/forti-client", stage / "forti-client")
shutil.copy2(root / "scripts/install-service.sh", stage / "install-service.sh")
shutil.copy2(root / "scripts/smoke-service.py", stage / "smoke-service.py")
for name in ("probe-connectivity.py", "probe_targets.py", "install-probe.sh", "probe-targets.json"):
    path = stage / name
    if path.exists() or path.is_symlink():
        path.unlink()
if probe_targets is not None:
    shutil.copy2(root / "scripts/probe-connectivity.py", stage / "probe-connectivity.py")
    copy_probe_module(root / "scripts/probe_targets.py", stage / "probe_targets.py")
    shutil.copy2(root / "scripts/install-probe.sh", stage / "install-probe.sh")
    shutil.copy2(probe_targets_path, stage / "probe-targets.json")
    os.chmod(stage / "probe-connectivity.py", 0o755)
    os.chmod(stage / "probe_targets.py", 0o755)
    os.chmod(stage / "install-probe.sh", 0o755)
    os.chmod(stage / "probe-targets.json", 0o644)
binary = "/Library/Application Support/FortiClient/forti-client"
for name, mode in [("daemon", "service"), ("agent", "agent")]:
    value = dict(Label=f"com.forti-client.{name}", ProgramArguments=[binary, mode],
                 RunAtLoad=True, KeepAlive=True, ThrottleInterval=30, ExitTimeOut=30,
                 ProcessType="Background", Umask=63,
                 EnvironmentVariables={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
    if name == "agent":
        value["LimitLoadToSessionType"] = "Aqua"
    else:
        # Worker logs are bounded by the daemon. No unbounded launchd log file.
        value["StandardOutPath"] = "/dev/null"
        value["StandardErrorPath"] = "/dev/null"
    file = stage / f"com.forti-client.{name}.plist"
    file.write_bytes(plistlib.dumps(value))
    subprocess.run(["/usr/bin/plutil", "-lint", str(file)], check=True)
print(f"Prepared installation in {stage}")
if probe_targets is None:
    print("Warning: probe-targets.json is absent; probe files were not staged.")
print("Review config.json and both plists before running install-service.sh as administrator.")
