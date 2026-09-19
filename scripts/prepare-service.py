#!/usr/bin/env python3
"""Stage a launchd installation from the existing local-run.sh; no privileged writes."""
import json
import os
import pathlib
import plistlib
import shlex
import shutil
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
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
shutil.copy2(root / "target/release/forti-client", stage / "forti-client")
shutil.copy2(root / "scripts/install-service.sh", stage / "install-service.sh")
shutil.copy2(root / "scripts/smoke-service.py", stage / "smoke-service.py")
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
print("Review config.json and both plists before running install-service.sh as administrator.")
